package gp

//go:generate stringer -type=GPO_LINK,GPOOptions -output=list_string_windows.go

import (
	"iter"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"tailscale.com/util/mak"
)

const _GPO_LIST_FLAG_MACHINE = 0x00000001

type GPO_LINK int32

const (
	GPLinkUnknown            GPO_LINK = 0
	GPLinkMachine            GPO_LINK = 1
	GPLinkSite               GPO_LINK = 2
	GPLinkDomain             GPO_LINK = 3
	GPLinkOrganizationalUnit GPO_LINK = 4
)

type _GROUP_POLICY_OBJECT struct {
	Options     GPOOptions
	Version     uint32
	DSPath      *uint16
	FileSysPath *uint16
	DisplayName *uint16
	GPOName     [50]uint16
	GPOLink     GPO_LINK
	LParam      uintptr
	Next        *_GROUP_POLICY_OBJECT
	Prev        *_GROUP_POLICY_OBJECT
	Extensions  *uint16
	LParam2     uintptr
	Link        *uint16
}

type GPOOptions uint32

const (
	GPO_FLAG_DISABLE GPOOptions = 0x00000001
	GPO_FLAG_FORCE   GPOOptions = 0x00000002
)

type GPOInfo struct {
	Options     GPOOptions
	DSPath      string
	FileSysPath string
	DisplayName string
	Name        string
	GPOLink     GPO_LINK
	Extensions  map[windows.GUID][]windows.GUID
	Link        string
}

func (gpoi *GPOInfo) IsDisabled() bool {
	return gpoi.Options&GPO_FLAG_DISABLE != 0
}

func (gpoi *GPOInfo) IsForced() bool {
	return gpoi.Options&GPO_FLAG_FORCE != 0
}

func (gpoi *GPOInfo) IsLocal() bool {
	return gpoi.Link == "Local"
}

func (gpoi *GPOInfo) IsMachine() bool {
	return strings.EqualFold(filepath.Base(gpoi.FileSysPath), "Machine")
}

// Note that the iterator must be consumed to avoid leakage
func AppliedGPOsForLocalMachine(extensionID *windows.GUID) (iter.Seq2[GPOInfo, error], error) {
	return appliedGPOs(true, nil, extensionID)
}

// Note that the iterator must be consumed to avoid leakage
func AppliedGPOsForUser(userSID *windows.SID, extensionID *windows.GUID) (iter.Seq2[GPOInfo, error], error) {
	return appliedGPOs(false, userSID, extensionID)
}

// We cannot use userSID as an indicator for machine as a nil userSID signifies
// the current user.
func appliedGPOs(machine bool, userSID *windows.SID, extensionID *windows.GUID) (iter.Seq2[GPOInfo, error], error) {
	var flags uint32
	if machine {
		flags |= _GPO_LIST_FLAG_MACHINE
	}

	var gpos *_GROUP_POLICY_OBJECT
	err := getAppliedGPOList(flags, nil, userSID, extensionID, &gpos)
	if err != nil {
		return nil, err
	}

	return func(yield func(GPOInfo, error) bool) {
		defer freeGPOList(gpos)
		for cgp := gpos; cgp != nil; cgp = cgp.Next {
			gpoInfo, err := makeGPOInfo(cgp)
			if !yield(gpoInfo, err) || err != nil {
				return
			}
		}
	}, nil
}

const guidStrLen = 38

func makeGPOInfo(gpo *_GROUP_POLICY_OBJECT) (result GPOInfo, err error) {
	var zero GPOInfo

	result.Options = gpo.Options
	result.DSPath = windows.UTF16PtrToString(gpo.DSPath)
	result.FileSysPath = windows.UTF16PtrToString(gpo.FileSysPath)
	result.DisplayName = windows.UTF16PtrToString(gpo.DisplayName)
	result.Name = windows.UTF16ToString(gpo.GPOName[:])
	result.GPOLink = gpo.GPOLink
	result.Link = windows.UTF16PtrToString(gpo.Link)

	strExtensions := windows.UTF16PtrToString(gpo.Extensions)
	strExtensions = strings.TrimPrefix(strExtensions, "[")
	strExtensions = strings.TrimSuffix(strExtensions, "]")
	for extLine := range strings.SplitSeq(strExtensions, "][") {
		if len(extLine) % guidStrLen != 0 {
			return zero, os.ErrInvalid
		}

		var guids []windows.GUID
		for len(extLine) > 0 {
			strGuid := extLine[:guidStrLen]
			guid, err := windows.GUIDFromString(strGuid)
			if err != nil {
				return zero, err
			}

			guids = append(guids, guid)
			extLine = extLine[guidStrLen:]
		}

		mak.Set(&result.Extensions, guids[0], guids[1:])
	}

	return result, nil
}
