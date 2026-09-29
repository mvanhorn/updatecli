package winres

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	rtManifest = 24
	manifestID = 1

	nsAssembly  = "urn:schemas-microsoft-com:asm.v1"
	nsTrustInfo = "urn:schemas-microsoft-com:asm.v3"

	resourceDirectorySize = 16
	resourceEntrySize     = 8
	resourceDataEntrySize = 16
	subdirectoryBit       = 0x80000000

	// PE32 optional header size excluding the data directories.
	optionalHeaderPrefixLen uint16 = 96

	// extraResourceBytes makes a fixture declare more manifest bytes than it stores.
	extraResourceBytes uint32 = 8

	windowsArtifactDirEnv = "UPDATECLI_WINDOWS_ARTIFACT_DIR"
)

var (
	errManifestAbsent         = errors.New("windows application manifest is absent")
	errManifestID             = errors.New("windows application manifest resource id is not 1")
	errManifestTruncated      = errors.New("windows application manifest resource data is truncated")
	errManifestMalformed      = errors.New("windows application manifest resource data is malformed")
	errManifestExecutionLevel = errors.New("windows application manifest must request asInvoker with uiAccess false")
)

func TestCommittedWindowsObjects(t *testing.T) {
	root := moduleRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "winres", "manifest.xml"))
	if err != nil {
		t.Fatalf("read manifest source: %v", err)
	}
	if err := validateExecutionLevel(source); err != nil {
		t.Fatalf("manifest source: %v", err)
	}

	objects := []struct {
		name    string
		file    string
		machine uint16
	}{
		{name: "amd64", file: "rsrc_windows_amd64.syso", machine: pe.IMAGE_FILE_MACHINE_AMD64},
		{name: "arm64", file: "rsrc_windows_arm64.syso", machine: pe.IMAGE_FILE_MACHINE_ARM64},
	}

	var embedded [][]byte
	for _, object := range objects {
		t.Run(object.name, func(t *testing.T) {
			f := openPE(t, filepath.Join(root, object.file))
			if f.Machine != object.machine {
				t.Fatalf("machine = %#x, want %#x", f.Machine, object.machine)
			}
			if f.OptionalHeader != nil {
				t.Fatal("committed resource object has a PE optional header")
			}
			manifest, err := executableManifest(f)
			if err != nil {
				t.Fatalf("executable manifest: %v", err)
			}
			if !bytes.Equal(manifest, source) {
				t.Fatalf("embedded manifest differs from winres/manifest.xml\nembedded: %q\nsource: %q", manifest, source)
			}
			assertAsInvokerManifest(t, manifest)
			embedded = append(embedded, manifest)
		})
	}
	if len(embedded) == 2 && !bytes.Equal(embedded[0], embedded[1]) {
		t.Fatal("amd64 and arm64 objects embed different manifests")
	}
}

func TestExecutionLevelFixtures(t *testing.T) {
	asInvoker := manifestXML("asInvoker", "false")
	cases := []struct {
		name string
		file []byte
		want error
	}{
		{
			name: "absent manifest",
			file: imageWithSection(".text", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, asInvoker),
			want: errManifestAbsent,
		},
		{
			name: "resource other than a manifest",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, resourceTree(3, manifestID, asInvoker, 0, 0)),
			want: errManifestAbsent,
		},
		{
			name: "wrong resource id",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, resourceTree(rtManifest, 2, asInvoker, 0, 0)),
			want: errManifestID,
		},
		{
			name: "truncated resource directory",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, truncatedResourceDirectory()),
			want: errManifestTruncated,
		},
		{
			name: "truncated resource data",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, resourceTree(rtManifest, manifestID, asInvoker, extraResourceBytes, 0)),
			want: errManifestTruncated,
		},
		{
			name: "malformed manifest",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, resourceTree(rtManifest, manifestID, []byte(`<?xml version="1.0"?><assembly`), 0, 0)),
			want: errManifestMalformed,
		},
		{
			name: "requireAdministrator",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, resourceTree(rtManifest, manifestID, manifestXML("requireAdministrator", "false"), 0, 0)),
			want: errManifestExecutionLevel,
		},
		{
			name: "uiAccess true",
			file: imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, 0, false, resourceTree(rtManifest, manifestID, manifestXML("asInvoker", "true"), 0, 0)),
			want: errManifestExecutionLevel,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := openBytes(t, tc.file)
			err := validateAsInvokerManifest(f)
			if !errors.Is(err, tc.want) {
				t.Fatalf("validateAsInvokerManifest() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLinkedImageReadsManifestByRVA(t *testing.T) {
	payload := manifestXML("asInvoker", "false")
	const virtualAddress uint32 = 0x2000
	body := resourceTree(rtManifest, manifestID, payload, 0, virtualAddress)
	f := openBytes(t, imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_ARM64, virtualAddress, true, body))
	if err := validateAsInvokerManifest(f); err != nil {
		t.Fatal(err)
	}

	admin := resourceTree(rtManifest, manifestID, manifestXML("requireAdministrator", "false"), 0, virtualAddress)
	f = openBytes(t, imageWithSection(".rsrc", pe.IMAGE_FILE_MACHINE_AMD64, virtualAddress, true, admin))
	if err := validateAsInvokerManifest(f); !errors.Is(err, errManifestExecutionLevel) {
		t.Fatalf("linked requireAdministrator error = %v", err)
	}
}

func TestWindowsReleaseArtifacts(t *testing.T) {
	dir := os.Getenv(windowsArtifactDirEnv)
	if dir == "" {
		t.Skip(windowsArtifactDirEnv + " is not set")
	}
	// #nosec G703 -- UPDATECLI_WINDOWS_ARTIFACT_DIR is an explicit tester-supplied directory.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("%s=%q: %v", windowsArtifactDirEnv, dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s=%q is not a directory", windowsArtifactDirEnv, dir)
	}

	found := map[uint16][]string{}
	// #nosec G703 -- UPDATECLI_WINDOWS_ARTIFACT_DIR is an explicit tester-supplied directory.
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		f, openErr := pe.Open(path)
		if openErr != nil {
			return nil
		}
		machine := f.Machine
		characteristics := f.Characteristics
		hasOptional := f.OptionalHeader != nil
		if closeErr := f.Close(); closeErr != nil {
			return closeErr
		}
		if !hasOptional || characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
			return nil
		}
		found[machine] = append(found[machine], path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}

	want := []struct {
		machine uint16
		name    string
	}{
		{machine: pe.IMAGE_FILE_MACHINE_AMD64, name: "amd64"},
		{machine: pe.IMAGE_FILE_MACHINE_ARM64, name: "arm64"},
	}
	var paths []string
	for _, target := range want {
		matches := found[target.machine]
		if len(matches) != 1 {
			t.Fatalf("%s: found %d Windows %s executables in %s, want exactly 1: %v", windowsArtifactDirEnv, len(matches), target.name, dir, matches)
		}
		delete(found, target.machine)
		paths = append(paths, matches[0])
	}
	if len(found) != 0 {
		t.Fatalf("%s contains Windows executables besides amd64 and arm64: %v", windowsArtifactDirEnv, found)
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			f := openPE(t, path)
			if err := validateAsInvokerManifest(f); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		})
	}
}

func validateAsInvokerManifest(f *pe.File) error {
	manifest, err := executableManifest(f)
	if err != nil {
		return err
	}
	return validateExecutionLevel(manifest)
}

func executableManifest(f *pe.File) ([]byte, error) {
	var section *pe.Section
	for _, candidate := range f.Sections {
		if candidate.Name == ".rsrc" {
			section = candidate
			break
		}
	}
	if section == nil {
		return nil, errManifestAbsent
	}
	raw, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errManifestTruncated, err)
	}

	typeOff, typeSub, found, err := findResourceID(raw, 0, rtManifest)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errManifestAbsent
	}
	if !typeSub {
		return nil, errManifestTruncated
	}

	idOff, idSub, found, err := findResourceID(raw, int(typeOff), manifestID)
	if err != nil {
		return nil, err
	}
	if !found {
		if resourceDirectoryHasID(raw, int(typeOff)) {
			return nil, errManifestID
		}
		return nil, errManifestAbsent
	}
	if !idSub {
		return nil, errManifestTruncated
	}

	dataOff, dataSub, found, err := firstResourceEntry(raw, int(idOff))
	if err != nil {
		return nil, err
	}
	if !found || dataSub {
		return nil, errManifestTruncated
	}
	return readResourceData(f, raw, int(dataOff))
}

func findResourceID(raw []byte, dirOff int, want uint32) (offset uint32, subdir, found bool, err error) {
	named, ids, entriesOff, err := resourceDirectory(raw, dirOff)
	if err != nil {
		return 0, false, false, err
	}
	for i := named; i < named+ids; i++ {
		name, dataOff, ok := resourceEntry(raw, entriesOff+i*resourceEntrySize)
		if !ok {
			return 0, false, false, errManifestTruncated
		}
		if name&subdirectoryBit != 0 || name != want {
			continue
		}
		return dataOff &^ subdirectoryBit, dataOff&subdirectoryBit != 0, true, nil
	}
	return 0, false, false, nil
}

func firstResourceEntry(raw []byte, dirOff int) (offset uint32, subdir, found bool, err error) {
	named, ids, entriesOff, err := resourceDirectory(raw, dirOff)
	if err != nil {
		return 0, false, false, err
	}
	if named+ids == 0 {
		return 0, false, false, nil
	}
	_, dataOff, ok := resourceEntry(raw, entriesOff)
	if !ok {
		return 0, false, false, errManifestTruncated
	}
	return dataOff &^ subdirectoryBit, dataOff&subdirectoryBit != 0, true, nil
}

func resourceDirectoryHasID(raw []byte, dirOff int) bool {
	_, ids, _, err := resourceDirectory(raw, dirOff)
	return err == nil && ids > 0
}

func resourceDirectory(raw []byte, dirOff int) (named, ids, entriesOff int, err error) {
	if dirOff < 0 || dirOff > len(raw) || len(raw)-dirOff < resourceDirectorySize {
		return 0, 0, 0, errManifestTruncated
	}
	named = int(binary.LittleEndian.Uint16(raw[dirOff+12:]))
	ids = int(binary.LittleEndian.Uint16(raw[dirOff+14:]))
	entriesOff = dirOff + resourceDirectorySize
	total := named + ids
	if total < named || entriesOff > len(raw) || total > (len(raw)-entriesOff)/resourceEntrySize {
		return 0, 0, 0, errManifestTruncated
	}
	return named, ids, entriesOff, nil
}

func resourceEntry(raw []byte, off int) (name, dataOff uint32, ok bool) {
	if off < 0 || off > len(raw) || len(raw)-off < resourceEntrySize {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(raw[off:]), binary.LittleEndian.Uint32(raw[off+4:]), true
}

func readResourceData(f *pe.File, raw []byte, off int) ([]byte, error) {
	if off < 0 || off > len(raw) || len(raw)-off < resourceDataEntrySize {
		return nil, errManifestTruncated
	}
	target := binary.LittleEndian.Uint32(raw[off:])
	size := binary.LittleEndian.Uint32(raw[off+4:])
	if size == 0 {
		return nil, errManifestTruncated
	}
	if f.OptionalHeader != nil {
		payload, ok, err := readRVA(f, target, size)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errManifestTruncated
		}
		return payload, nil
	}
	end := uint64(target) + uint64(size)
	if uint64(target) > uint64(len(raw)) || end > uint64(len(raw)) || end < uint64(target) {
		return nil, errManifestTruncated
	}
	return raw[target:end], nil
}

func readRVA(f *pe.File, rva, size uint32) ([]byte, bool, error) {
	for _, section := range f.Sections {
		if rva < section.VirtualAddress {
			continue
		}
		delta := rva - section.VirtualAddress
		if uint64(delta)+uint64(size) > uint64(section.Size) {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return nil, false, fmt.Errorf("%w: %s", errManifestTruncated, err)
		}
		return data[delta : delta+size], true, nil
	}
	return nil, false, nil
}

func validateExecutionLevel(manifest []byte) error {
	level, uiAccess, err := parseExecutionLevel(manifest)
	if err != nil {
		return err
	}
	if level != "asInvoker" || uiAccess != "false" {
		return fmt.Errorf("%w: level=%q uiAccess=%q", errManifestExecutionLevel, level, uiAccess)
	}
	return nil
}

func assertAsInvokerManifest(t *testing.T, manifest []byte) {
	t.Helper()
	level, uiAccess, err := parseExecutionLevel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if level != "asInvoker" || uiAccess != "false" {
		t.Fatalf("level=%q uiAccess=%q", level, uiAccess)
	}
}

func parseExecutionLevel(manifest []byte) (level, uiAccess string, err error) {
	dec := xml.NewDecoder(bytes.NewReader(manifest))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("%w: charset %s", errManifestMalformed, charset)
	}
	var assembly, trust, sawLevel bool
	for {
		tok, decErr := dec.Token()
		if errors.Is(decErr, io.EOF) {
			break
		}
		if decErr != nil {
			return "", "", fmt.Errorf("%w: %s", errManifestMalformed, decErr)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case start.Name.Local == "assembly" && start.Name.Space == nsAssembly:
			assembly = true
		case start.Name.Local == "trustInfo" && start.Name.Space == nsTrustInfo:
			trust = true
		case start.Name.Local == "requestedExecutionLevel" && start.Name.Space == nsTrustInfo:
			sawLevel = true
			level = xmlAttr(start, "level")
			uiAccess = xmlAttr(start, "uiAccess")
		}
	}
	if !assembly || !trust || !sawLevel {
		return "", "", fmt.Errorf("%w: missing namespaced requestedExecutionLevel", errManifestMalformed)
	}
	return level, uiAccess, nil
}

func xmlAttr(start xml.StartElement, local string) string {
	for _, attr := range start.Attr {
		if attr.Name.Local == local && attr.Name.Space == "" {
			return attr.Value
		}
	}
	return ""
}

func manifestXML(level, uiAccess string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="%s" manifestVersion="1.0">
  <trustInfo xmlns="%s">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="%s" uiAccess="%s"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
`, nsAssembly, nsTrustInfo, level, uiAccess))
}

// resourceTree builds a type/id/language resource directory.
// extraBytes inflates the declared manifest size past the stored payload.
// rvaBase is added to the data pointer so a linked PE fixture can store an RVA.
func resourceTree(typeID, nameID uint32, payload []byte, extraBytes, rvaBase uint32) []byte {
	claimedSize := u32len(len(payload))
	if extraBytes > math.MaxUint32-claimedSize {
		panic("claimed manifest size overflows uint32")
	}
	claimedSize += extraBytes
	const (
		nameDir   = 24
		langDir   = 48
		dataEntry = 72
		data      = 88
		langID    = 0x0409
	)
	buf := make([]byte, data+len(payload))
	putResourceID(buf[0:], typeID, subdirectoryBit|nameDir)
	putResourceID(buf[nameDir:], nameID, subdirectoryBit|langDir)
	putResourceID(buf[langDir:], langID, dataEntry)
	binary.LittleEndian.PutUint32(buf[dataEntry:], rvaBase+data)
	binary.LittleEndian.PutUint32(buf[dataEntry+4:], claimedSize)
	copy(buf[data:], payload)
	return buf
}

func putResourceID(dir []byte, id, offset uint32) {
	binary.LittleEndian.PutUint16(dir[14:], 1)
	binary.LittleEndian.PutUint32(dir[16:], id)
	binary.LittleEndian.PutUint32(dir[20:], offset)
}

func truncatedResourceDirectory() []byte {
	dir := make([]byte, resourceDirectorySize)
	binary.LittleEndian.PutUint16(dir[14:], 50)
	return dir
}

func imageWithSection(name string, machine uint16, virtualAddress uint32, optionalHeader bool, raw []byte) []byte {
	var file bytes.Buffer
	var optional []byte
	var optionalSize uint16
	const (
		fileHeaderBytes    uint32 = 20
		sectionHeaderBytes uint32 = 40
	)
	if binary.Size(pe.FileHeader{}) != int(fileHeaderBytes) || binary.Size(pe.SectionHeader32{}) != int(sectionHeaderBytes) {
		panic("unexpected COFF header size")
	}
	rawOff := fileHeaderBytes
	if optionalHeader {
		optional = optionalHeader32Prefix()
		optionalSize = optionalHeaderPrefixLen
		rawOff += uint32(optionalHeaderPrefixLen)
	}
	rawOff += sectionHeaderBytes
	hdr := pe.FileHeader{
		Machine:              machine,
		NumberOfSections:     1,
		SizeOfOptionalHeader: optionalSize,
		Characteristics:      pe.IMAGE_FILE_EXECUTABLE_IMAGE,
	}
	if err := binary.Write(&file, binary.LittleEndian, &hdr); err != nil {
		panic(err)
	}
	file.Write(optional)
	sectionLen := u32len(len(raw))
	var sectionName [8]byte
	copy(sectionName[:], name)
	section := pe.SectionHeader32{
		Name:             sectionName,
		VirtualSize:      sectionLen,
		VirtualAddress:   virtualAddress,
		SizeOfRawData:    sectionLen,
		PointerToRawData: rawOff,
		Characteristics:  pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ,
	}
	if err := binary.Write(&file, binary.LittleEndian, &section); err != nil {
		panic(err)
	}
	file.Write(raw)
	// debug/pe probes 96 bytes at offset zero before it decides the file is COFF.
	if file.Len() < 96 {
		file.Write(make([]byte, 96-file.Len()))
	}
	return file.Bytes()
}

func optionalHeader32Prefix() []byte {
	var header pe.OptionalHeader32
	header.Magic = 0x10b
	header.Subsystem = 3
	prefix := binary.Size(header) - binary.Size(header.DataDirectory)
	if prefix != int(optionalHeaderPrefixLen) {
		panic("unexpected PE32 optional header size")
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
	return buf.Bytes()[:prefix]
}

func u32len(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("length overflows uint32")
	}
	return uint32(n)
}

func openPE(t *testing.T, path string) *pe.File {
	t.Helper()
	f, err := pe.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	})
	return f
}

func openBytes(t *testing.T, body []byte) *pe.File {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	return filepath.Dir(filepath.Dir(file))
}
