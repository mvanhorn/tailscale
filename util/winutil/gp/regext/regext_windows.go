package regext

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var REGISTRY_EXTENSION_GUID = windows.GUID{0x35378EAC, 0x683F, 0x11D2, [8]byte{0xA8, 0x9A, 0x00, 0xC0, 0x4F, 0xBB, 0xCF, 0xA2}}

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrStringTruncated  = errors.New("string truncated due to excessive length")
	ErrUnknownVersion   = errors.New("unknown version")
)

const (
	maxKeyLength       = 255
	maxValueNameLength = 16383
	maxValueLength     = 2048 // recommended, not a hard limit
)

type UnknownValueTypeError struct {
	ValueType uint32
}

func (e *UnknownValueTypeError) Error() string {
	return fmt.Sprintf("Unknown registry value type 0x%08X", e.ValueType)
}

type UnexpectedDataLengthError struct {
	WantLen int
	GotLen  int
}

func (e *UnexpectedDataLengthError) Error() string {
	return fmt.Sprintf("Unexpected data length error: got %d, want %d", e.GotLen, e.WantLen)
}

type InvalidDataLengthForTypeError struct {
	ValueType uint32
	GotLen    uint32
}

func (e *InvalidDataLengthForTypeError) Error() string {
	return fmt.Sprintf("Invalid data length for type %d: %d", e.ValueType, e.GotLen)
}

type UnexpectedCodeUnitError struct {
	WantCodeUnit uint16
	GotCodeUnit  uint16
}

func (e *UnexpectedCodeUnitError) Error() string {
	return fmt.Sprintf("Unexpected UTF-16LE code unit: got 0x%04X, want 0x%04X", e.GotCodeUnit, e.WantCodeUnit)
}

type StringReadError struct {
	Inner error
}

func (e *StringReadError) Error() string {
	return fmt.Sprintf("Reading nul-terminated UTF-16LE: %v", e.Inner)
}

func (e *StringReadError) Unwrap() error {
	return e.Inner
}

const (
	_REGFILE_SIGNATURE     = 0x67655250
	_REGISTRY_FILE_VERSION = 0x00000001
	_DELETEKEYS            = "**DeleteKeys"
	_SECUREKEY             = "**SecureKey"
	_SOFT                  = "**soft."
	_COMMENT               = "**Comment:"
	_DELETEVALUES          = "**DeleteValues"
	_DEL_VALUENAME         = "**Del."
	_DELVALS               = "**DelVals"
)

type RegistryCommand struct {
	SubKey                  string
	ValueName               string
	ValueType               uint32
	Data                    []byte
	DataTruncatedFromLength uint32
}

const polFileLeafName = "registry.pol"

func NewReaderFromPolicyPath(policyFileSysPath string) (result *Reader, err error) {
	polFilePath := filepath.Join(policyFileSysPath, polFileLeafName)
	f, err := os.Open(polFilePath)
	if err != nil {
		return nil, err
	}

	return NewReaderTakeOwnership(f)
}

func NewReader(r io.ReadSeeker) (result *Reader, err error) {
	if r == nil {
		return nil, os.ErrInvalid
	}

	rpr := &Reader{r: r}
	if err := rpr.readHeader(); err != nil {
		return nil, err
	}
	return rpr, nil
}

func NewReaderTakeOwnership(r io.ReadSeeker) (result *Reader, err error) {
	if r == nil {
		return nil, os.ErrInvalid
	}

	rpr := &Reader{r: r, own: true}
	if err := rpr.readHeader(); err != nil {
		if c, ok := r.(io.Closer); ok {
			c.Close()
		}
		return nil, err
	}
	return rpr, nil
}

func (rpr *Reader) Entries() iter.Seq2[RegistryCommand, error] {
	return func(yield func(RegistryCommand, error) bool) {
		for {
			rc, err := rpr.nextCommand()
			if err == io.EOF {
				return
			}
			if !yield(rc, err) || err != nil {
				return
			}
		}
	}
}

type Reader struct {
	r   io.ReadSeeker
	own bool
}

func (rpr *Reader) Close() error {
	if !rpr.own {
		return nil
	}

	if c, ok := rpr.r.(io.Closer); ok {
		err := c.Close()
		if err == nil {
			rpr.r = nil
			return err
		}
	}

	return nil
}

func (rpr *Reader) readHeader() error {
	var sig uint32
	if err := binary.Read(rpr.r, binary.LittleEndian, &sig); err != nil {
		return err
	}
	if sig != _REGFILE_SIGNATURE {
		return ErrInvalidSignature
	}

	var ver uint32
	if err := binary.Read(rpr.r, binary.LittleEndian, &ver); err != nil {
		return err
	}
	if ver != _REGISTRY_FILE_VERSION {
		return ErrUnknownVersion
	}
	return nil
}

func (rpr *Reader) nextCommand() (rc RegistryCommand, err error) {
	var zero RegistryCommand
	if err := rpr.readCodeUnit('['); err != nil {
		return zero, err
	}

	rc.SubKey, err = rpr.readNulTerminated(maxKeyLength)
	if err != nil {
		return zero, err
	}

	if err := rpr.readCodeUnit(';'); err != nil {
		return zero, err
	}

	rc.ValueName, err = rpr.readNulTerminated(maxValueNameLength)
	if err != nil {
		return zero, err
	}

	if err := rpr.readCodeUnit(';'); err != nil {
		return zero, err
	}

	rc.ValueType, err = rpr.readValueType()
	if err != nil {
		return zero, err
	}

	if err := rpr.readCodeUnit(';'); err != nil {
		return zero, err
	}

	rc.Data, rc.DataTruncatedFromLength, err = rpr.readData(rc.ValueType)
	if err != nil {
		return zero, err
	}

	if err := rpr.readCodeUnit(']'); err != nil {
		return zero, err
	}

	return rc, nil
}

// TODO ASK: Maximum size for entire file; 100MiB as of 8.1
func (rpr *Reader) readData(valueType uint32) (result []byte, truncatedFromLength uint32, err error) {
	var actualLen uint32
	if err := binary.Read(rpr.r, binary.LittleEndian, &actualLen); err != nil {
		return nil, 0, err
	}

	// Error out if value length does not make sense for the value type
	switch valueType {
	case registry.DWORD, registry.DWORD_BIG_ENDIAN:
		if actualLen != uint32(unsafe.Sizeof(uint32(0))) {
			return nil, 0, &InvalidDataLengthForTypeError{
				ValueType: valueType,
				GotLen:    actualLen,
			}
		}
	case registry.QWORD:
		if actualLen != uint32(unsafe.Sizeof(uint64(0))) {
			return nil, 0, &InvalidDataLengthForTypeError{
				ValueType: valueType,
				GotLen:    actualLen,
			}
		}
	case registry.SZ, registry.MULTI_SZ, registry.EXPAND_SZ, registry.LINK:
		if actualLen % uint32(unsafe.Sizeof(uint16(0))) != 0 {
			return nil, 0, &InvalidDataLengthForTypeError{
				ValueType: valueType,
				GotLen:    actualLen,
			}
		}
	case registry.NONE:
		if actualLen != 0 {
			return nil, 0, &InvalidDataLengthForTypeError{
				ValueType: valueType,
				GotLen:    actualLen,
			}
		}
	default:
	}

	if err := rpr.readCodeUnit(';'); err != nil {
		return nil, 0, err
	}

	dataLen := actualLen
	truncated := actualLen > maxValueLength
	if truncated {
		dataLen = maxValueLength
	}

	result = make([]byte, dataLen)
	n, err := rpr.r.Read(result)
	if err != nil {
		return nil, 0, err
	}
	if n != len(result) {
		return nil, 0, &UnexpectedDataLengthError{
			WantLen: len(result),
			GotLen:  n,
		}
	}

	if truncated {
		offset := int64(actualLen - dataLen)
		if _, err := rpr.r.Seek(offset, io.SeekCurrent); err != nil {
			return nil, actualLen, err
		}
	}

	return result, 0, nil
}

func (rpr *Reader) readCodeUnit(wantCodeUnit uint16) error {
	var gotCodeUnit uint16
	if err := binary.Read(rpr.r, binary.LittleEndian, &gotCodeUnit); err != nil {
		return err
	}
	if wantCodeUnit != gotCodeUnit {
		return &UnexpectedCodeUnitError{
			WantCodeUnit: wantCodeUnit,
			GotCodeUnit:  gotCodeUnit,
		}
	}
	return nil
}

func (rpr *Reader) readNulTerminated(maxLen int) (string, error) {
	// maxKeyLength is a decent initial capacity for both key and value name
	buf := make([]uint16, 0, maxKeyLength)
	for {
		var codeUnit uint16
		if err := binary.Read(rpr.r, binary.LittleEndian, &codeUnit); err != nil {
			return "", &StringReadError{Inner: err}
		}
		if codeUnit == 0 {
			break
		}
		buf = append(buf, codeUnit)
		if len(buf) == maxLen {
			return windows.UTF16ToString(buf[:]), ErrStringTruncated
		}
	}

	return windows.UTF16ToString(buf[:]), nil
}

func (rpr *Reader) readValueType() (result uint32, err error) {
	if err := binary.Read(rpr.r, binary.LittleEndian, &result); err != nil {
		return 0, err
	}

	switch result {
	case registry.NONE, registry.SZ, registry.EXPAND_SZ, registry.BINARY, registry.DWORD, registry.DWORD_BIG_ENDIAN, registry.LINK, registry.MULTI_SZ, registry.QWORD:
		return result, nil
	default:
		return 0, &UnknownValueTypeError{ValueType: result}
	}
}
