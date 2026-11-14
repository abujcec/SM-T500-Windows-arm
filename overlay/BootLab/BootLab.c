/** @file
  T500 BootLab v0.6: verbose Windows Boot Manager chainload diagnostics.

  Scans UEFI Simple File System handles and attempts to load and start the
  existing Windows Boot Manager. This application does not intentionally
  write partitions, BCD, EFI files, or NVRAM.
**/

#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Guid/FileInfo.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/DevicePathLib.h>
#include <Library/PeCoffLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/CacheMaintenanceLib.h>

#define WINDOWS_BOOT_MANAGER_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
#define WINDOWS_IMAGE_BOOT_MANAGER_PATH L"\\Windows\\Boot\\EFI\\bootmgfw.efi"
#define PROBE_EFI_PATH L"\\EFI\\Microsoft\\Boot\\SecureBootRecovery.efi"
#define BOOTMGR_EFI_PATH L"\\EFI\\Microsoft\\Boot\\bootmgr.efi"
#define NTFS_DRIVER_PATH L"\\EFI\\Boot\\ntfs_aa64.efi"

typedef struct {
  UINT8  *Source;
  UINTN  SourceSize;
} BOOTLAB_IMAGE_SOURCE;

STATIC
RETURN_STATUS
EFIAPI
BootLabImageRead (
  IN     VOID   *FileHandle,
  IN     UINTN  FileOffset,
  IN OUT UINTN  *ReadSize,
  OUT    VOID   *Buffer
  )
{
  BOOTLAB_IMAGE_SOURCE *Source;
  UINTN                Available;

  if ((FileHandle == NULL) || (ReadSize == NULL) || (Buffer == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  Source = (BOOTLAB_IMAGE_SOURCE *)FileHandle;
  if (FileOffset >= Source->SourceSize) {
    *ReadSize = 0;
    return RETURN_SUCCESS;
  }

  Available = Source->SourceSize - FileOffset;
  if (*ReadSize > Available) {
    *ReadSize = Available;
  }

  CopyMem (Buffer, Source->Source + FileOffset, *ReadSize);
  return RETURN_SUCCESS;
}

STATIC
EFI_STATUS
LoadPeCoffImage (
  IN  EFI_HANDLE  ParentImage,
  IN  EFI_HANDLE  DeviceHandle,
  IN  CHAR16      *ImagePath,
  IN  VOID        *SourceBuffer,
  IN  UINTN       SourceSize
  )
{
  EFI_STATUS                     Status;
  PE_COFF_LOADER_IMAGE_CONTEXT  Context;
  BOOTLAB_IMAGE_SOURCE          Source;
  EFI_PHYSICAL_ADDRESS          Allocation;
  EFI_PHYSICAL_ADDRESS          ImageBase;
  UINTN                         Pages;
  EFI_LOADED_IMAGE_PROTOCOL     LoadedImage;
  EFI_HANDLE                    ImageHandle;
  EFI_DEVICE_PATH_PROTOCOL      *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL      *HandlePath;
  UINTN                          DevicePathPrefixSize;
  UINTN                          FullDevicePathSize;
  EFI_IMAGE_ENTRY_POINT         EntryPoint;

  ZeroMem (&Context, sizeof (Context));
  Source.Source = (UINT8 *)SourceBuffer;
  Source.SourceSize = SourceSize;
  Context.Handle = &Source;
  Context.ImageRead = BootLabImageRead;

  Status = PeCoffLoaderGetImageInfo (&Context);
  if (EFI_ERROR (Status)) {
    Print (L"[PECOFF] GetImageInfo failed: %r\n", Status);
    return Status;
  }
  if (Context.Machine != EFI_IMAGE_MACHINE_AARCH64 ||
      Context.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION ||
      Context.ImageSize == 0 || Context.ImageSize > MAX_UINTN) {
    Print (L"[PECOFF] Unsupported machine/subsystem/size: %u/%u/0x%lx\n",
           Context.Machine, Context.ImageType, Context.ImageSize);
    return EFI_UNSUPPORTED;
  }

  if (Context.SectionAlignment == 0 || Context.ImageSize > MAX_UINTN - Context.SectionAlignment) {
    return EFI_LOAD_ERROR;
  }
  Pages = EFI_SIZE_TO_PAGES ((UINTN)Context.ImageSize + Context.SectionAlignment);
  Allocation = 0;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiLoaderCode, Pages, &Allocation);
  if (EFI_ERROR (Status)) {
    Print (L"[PECOFF] AllocatePages failed: %r\n", Status);
    return Status;
  }

  ImageBase = Allocation;
  if (Context.SectionAlignment > EFI_PAGE_SIZE) {
    ImageBase = (ImageBase + Context.SectionAlignment - 1) &
                           ~((EFI_PHYSICAL_ADDRESS)Context.SectionAlignment - 1);
  }
  Context.ImageAddress = ImageBase;
  Context.DestinationAddress = ImageBase;
  Status = PeCoffLoaderLoadImage (&Context);
  if (EFI_ERROR (Status)) {
    Print (L"[PECOFF] LoadImage failed: %r\n", Status);
    gBS->FreePages (Allocation, Pages);
    return Status;
  }
  Status = PeCoffLoaderRelocateImage (&Context);
  if (EFI_ERROR (Status)) {
    Print (L"[PECOFF] RelocateImage failed: %r\n", Status);
    gBS->FreePages (Allocation, Pages);
    return Status;
  }

  ZeroMem (&LoadedImage, sizeof (LoadedImage));
  LoadedImage.Revision = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
  LoadedImage.ParentHandle = ParentImage;
  LoadedImage.SystemTable = gST;
  LoadedImage.DeviceHandle = DeviceHandle;
  HandlePath = DevicePathFromHandle (DeviceHandle);
  DevicePath = FileDevicePath (DeviceHandle, ImagePath);
  if ((DevicePath == NULL) || (HandlePath == NULL)) {
    if (DevicePath != NULL) {
      gBS->FreePool (DevicePath);
    }
    gBS->FreePages (Allocation, Pages);
    return EFI_OUT_OF_RESOURCES;
  }
  DevicePathPrefixSize = GetDevicePathSize (HandlePath) - sizeof (EFI_DEVICE_PATH_PROTOCOL);
  FullDevicePathSize = GetDevicePathSize (DevicePath);
  if ((DevicePathPrefixSize >= FullDevicePathSize) ||
      (DevicePathPrefixSize + sizeof (EFI_DEVICE_PATH_PROTOCOL) >= FullDevicePathSize)) {
    Print (L"[PECOFF] Invalid device path split: prefix=0x%lx full=0x%lx\n",
           (UINT64)DevicePathPrefixSize, (UINT64)FullDevicePathSize);
    gBS->FreePool (DevicePath);
    gBS->FreePages (Allocation, Pages);
    return EFI_LOAD_ERROR;
  }
  LoadedImage.FilePath = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)DevicePath + DevicePathPrefixSize);
  LoadedImage.ImageBase = (VOID *)(UINTN)ImageBase;
  LoadedImage.ImageSize = (UINTN)Context.ImageSize;
  LoadedImage.ImageCodeType = EfiLoaderCode;
  LoadedImage.ImageDataType = EfiLoaderData;
  ImageHandle = NULL;
  Status = gBS->InstallProtocolInterface (&ImageHandle, &gEfiLoadedImageProtocolGuid,
                                          EFI_NATIVE_INTERFACE, &LoadedImage);
  if (EFI_ERROR (Status)) {
    Print (L"[PECOFF] Install LoadedImage protocol failed: %r\n", Status);
    gBS->FreePool (DevicePath);
    gBS->FreePages (Allocation, Pages);
    return Status;
  }
  Status = gBS->InstallProtocolInterface (&ImageHandle, &gEfiLoadedImageDevicePathProtocolGuid,
                                          EFI_NATIVE_INTERFACE, DevicePath);
  if (EFI_ERROR (Status)) {
    Print (L"[PECOFF] Install LoadedImageDevicePath failed: %r\n", Status);
    gBS->UninstallProtocolInterface (ImageHandle, &gEfiLoadedImageProtocolGuid, &LoadedImage);
    gBS->FreePool (DevicePath);
    gBS->FreePages (Allocation, Pages);
    return Status;
  }

  InvalidateInstructionCacheRange ((VOID *)(UINTN)Context.ImageAddress, (UINTN)Context.ImageSize);
  EntryPoint = (EFI_IMAGE_ENTRY_POINT)(UINTN)Context.EntryPoint;
  Print (L"[PECOFF] Device=%p full-path=%p file-path=%p\n",
         DeviceHandle, DevicePath, LoadedImage.FilePath);
  Print (L"[PECOFF] Entry=%p base=%p size=0x%lx; calling Windows Boot Manager entry...\n",
         EntryPoint, (VOID *)(UINTN)Context.ImageAddress, Context.ImageSize);
  Status = EntryPoint (ImageHandle, gST);
  Print (L"[PECOFF] Windows image returned: %r\n", Status);
  gBS->UninstallProtocolInterface (ImageHandle, &gEfiLoadedImageDevicePathProtocolGuid, DevicePath);
  gBS->UninstallProtocolInterface (ImageHandle, &gEfiLoadedImageProtocolGuid, &LoadedImage);
  gBS->FreePool (DevicePath);
  gBS->FreePages (Allocation, Pages);
  return Status;
}

STATIC
EFI_STATUS
ReadFileBuffer (
  IN EFI_HANDLE       FsHandle,
  IN CHAR16            *Path,
  OUT VOID             **Buffer,
  OUT UINTN            *BufferSize
  )
{
  EFI_STATUS Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;
  EFI_FILE_INFO *Info;
  UINTN InfoSize;
  UINTN Size;

  *Buffer = NULL;
  *BufferSize = 0;
  Fs = NULL; Root = NULL; File = NULL; Info = NULL;
  Status = gBS->HandleProtocol(FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR(Status)) return Status;
  Status = Fs->OpenVolume(Fs, &Root);
  if (EFI_ERROR(Status)) return Status;
  Status = Root->Open(Root, &File, Path, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) { Root->Close(Root); return Status; }
  InfoSize = 0;
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) { File->Close(File); Root->Close(Root); return Status; }
  Status = gBS->AllocatePool(EfiLoaderData, InfoSize, (VOID **)&Info);
  if (EFI_ERROR(Status)) { File->Close(File); Root->Close(Root); return Status; }
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, Info);
  if (!EFI_ERROR(Status)) {
    Size = (UINTN)Info->FileSize;
    Status = gBS->AllocatePool(EfiLoaderData, Size, Buffer);
    if (!EFI_ERROR(Status)) {
      *BufferSize = Size;
      Status = File->Read(File, BufferSize, *Buffer);
      if (EFI_ERROR(Status)) { gBS->FreePool(*Buffer); *Buffer = NULL; *BufferSize = 0; }
    }
  }
  gBS->FreePool(Info);
  File->Close(File);
  Root->Close(Root);
  return Status;
}

STATIC
VOID
LoadNtfsDriver (IN EFI_HANDLE ImageHandle, IN EFI_HANDLE EspHandle)
{
  EFI_DEVICE_PATH_PROTOCOL *Path;
  EFI_HANDLE DriverImage;
  EFI_STATUS Status;
  UINTN ExitDataSize;
  CHAR16 *ExitData;
  EFI_HANDLE *Handles;
  UINTN Count;
  UINTN I;
  Path = FileDevicePath(EspHandle, NTFS_DRIVER_PATH);
  DriverImage = NULL; ExitDataSize = 0; ExitData = NULL;
  Print(L"[NTFS] Loading ARM64 NTFS driver...\n");
  Status = gBS->LoadImage(FALSE, ImageHandle, Path, NULL, 0, &DriverImage);
  Print(L"[NTFS] LoadImage returned: %r (0x%lx), handle=%p\n", Status, (UINT64)Status, DriverImage);
  if (!EFI_ERROR(Status)) {
    Status = gBS->StartImage(DriverImage, &ExitDataSize, &ExitData);
    Print(L"[NTFS] StartImage returned: %r (0x%lx)\n", Status, (UINT64)Status);
    if (ExitData != NULL) gBS->FreePool(ExitData);
    Handles = NULL; Count = 0;
    if (!EFI_ERROR(gBS->LocateHandleBuffer(AllHandles, NULL, NULL, &Count, &Handles))) {
      for (I = 0; I < Count; I++) gBS->ConnectController(Handles[I], NULL, NULL, TRUE);
      gBS->FreePool(Handles);
    }
  }
  if (Path != NULL) gBS->FreePool(Path);
}

STATIC
VOID
FindFileSystemForPath (IN CHAR16 *SearchPath, OUT EFI_HANDLE *Result)
{
  EFI_HANDLE *Handles;
  UINTN Count;
  UINTN I;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_FILE_PROTOCOL *Root;
  EFI_FILE_PROTOCOL *File;
  EFI_STATUS S;
  *Result = NULL;
  Handles = NULL; Count = 0;
  S = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR(S)) return;
  for (I = 0; I < Count; I++) {
    Fs = NULL; Root = NULL; File = NULL;
    if (EFI_ERROR(gBS->HandleProtocol(Handles[I], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs))) continue;
    if (EFI_ERROR(Fs->OpenVolume(Fs, &Root))) continue;
    S = Root->Open(Root, &File, SearchPath, EFI_FILE_MODE_READ, 0);
    if (!EFI_ERROR(S) && File != NULL) {
      File->Close(File); Root->Close(Root); *Result = Handles[I]; break;
    }
    Root->Close(Root);
  }
  if (Handles != NULL) gBS->FreePool(Handles);
}

STATIC
VOID
RunLoadProbe (IN EFI_HANDLE ImageHandle, IN EFI_HANDLE FsHandle)
{
  EFI_DEVICE_PATH_PROTOCOL *Path;
  EFI_HANDLE ProbeImage;
  EFI_STATUS Status;
  EFI_STATUS StartStatus;
  UINTN ExitDataSize;
  CHAR16 *ExitData;
  VOID *Buffer;
  UINTN BufferSize;
  EFI_HANDLE WindowsHandle;
  EFI_STATUS PeStatus;

  Path = FileDevicePath(FsHandle, PROBE_EFI_PATH);
  ProbeImage = NULL;
  Print(L"\n[PROBE A] Loading signed ARM64 probe from device path...\n");
  Status = gBS->LoadImage(FALSE, ImageHandle, Path, NULL, 0, &ProbeImage);
  Print(L"[PROBE A] LoadImage returned: %r (0x%lx), handle=%p\n", Status, (UINT64)Status, ProbeImage);
  if (!EFI_ERROR(Status)) gBS->UnloadImage(ProbeImage);
  if (Path != NULL) gBS->FreePool(Path);

  Path = FileDevicePath(FsHandle, BOOTMGR_EFI_PATH);
  ProbeImage = NULL;
  ExitDataSize = 0;
  ExitData = NULL;
  Print(L"[PROBE A2] Loading Windows bootmgr.efi from device path...\n");
  Status = gBS->LoadImage(FALSE, ImageHandle, Path, NULL, 0, &ProbeImage);
  Print(L"[PROBE A2] LoadImage returned: %r (0x%lx), handle=%p\n", Status, (UINT64)Status, ProbeImage);
  if (!EFI_ERROR(Status)) {
    Print(L"[PROBE A2] Starting bootmgr.efi...\n");
    StartStatus = gBS->StartImage(ProbeImage, &ExitDataSize, &ExitData);
    Print(L"[PROBE A2] StartImage returned: %r (0x%lx), exit-size=%u\n", StartStatus, (UINT64)StartStatus, ExitDataSize);
    if (ExitData != NULL) gBS->FreePool(ExitData);
    gBS->UnloadImage(ProbeImage);
  }
  if (Path != NULL) gBS->FreePool(Path);

  WindowsHandle = NULL;
  FindFileSystemForPath(WINDOWS_IMAGE_BOOT_MANAGER_PATH, &WindowsHandle);
  if (WindowsHandle != NULL) {
    Print(L"[PROBE B] NTFS Windows partition found (handle=%p).\n", WindowsHandle);
  } else {
    Print(L"[PROBE B] NTFS Windows partition was not found; testing ESP copy.\n");
  }
  Buffer = NULL; BufferSize = 0; ProbeImage = NULL;
  Print(L"[PROBE B] Reading ESP Boot Manager into memory...\n");
  Print(L"[PROBE B] Device: selected ESP handle %p\n", FsHandle);
  Print(L"[PROBE B] Path: %s\n", WINDOWS_BOOT_MANAGER_PATH);
  Status = ReadFileBuffer(FsHandle, WINDOWS_BOOT_MANAGER_PATH, &Buffer, &BufferSize);
  Print(L"[PROBE B] Read returned: %r (0x%lx), size=0x%lx\n", Status, (UINT64)Status, (UINT64)BufferSize);
  if (!EFI_ERROR(Status)) {
    Print(L"[PROBE B] Calling EDK2 PE/COFF loader...\n");
    PeStatus = LoadPeCoffImage(ImageHandle, FsHandle, WINDOWS_BOOT_MANAGER_PATH, Buffer, BufferSize);
    Print(L"[PROBE B] PE/COFF loader returned: %r (0x%lx)\n", PeStatus, (UINT64)PeStatus);
    gBS->FreePool(Buffer);
  }
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                       Status;
  EFI_STATUS                       StartStatus;
  EFI_STATUS                       ImageProtocolStatus;
  UINTN                            HandleCount;
  EFI_HANDLE                       *Handles;
  EFI_HANDLE                       FoundHandle;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *FileSystem;
  EFI_FILE_PROTOCOL                *Root;
  EFI_FILE_PROTOCOL                *File;
  EFI_DEVICE_PATH_PROTOCOL         *BootManagerPath;
  EFI_HANDLE                       WindowsImage;
  EFI_LOADED_IMAGE_PROTOCOL        *LoadedImage;
  UINTN                            Index;
  UINTN                            ExitDataSize;
  CHAR16                           *ExitData;

  (VOID)SystemTable;

  FoundHandle = NULL;
  Handles = NULL;
  HandleCount = 0;
  BootManagerPath = NULL;
  WindowsImage = NULL;
  LoadedImage = NULL;
  ExitDataSize = 0;
  ExitData = NULL;

  Print(L"\n========================================\n");
  Print(L"          T500 BootLab v0.6              \n");
  Print(L"========================================\n");
  Print(L"Verbose Windows ARM64 chainload test\n");
  Print(L"Firmware vendor  : %s\n", gST->FirmwareVendor);
  Print(L"Firmware revision: 0x%08x\n", gST->FirmwareRevision);
  Print(L"SystemTable      : %p\n", SystemTable);
  Print(L"Parent image     : %p\n", ImageHandle);

  Print(L"\n[ENUM 01] Calling LocateHandleBuffer(SimpleFileSystem)...\n");
  Status = gBS->LocateHandleBuffer(
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  Print(L"[ENUM 02] LocateHandleBuffer returned: %r (0x%lx)\n",
        Status, (UINT64)Status);

  if (EFI_ERROR(Status)) {
    goto Done;
  }

  Print(L"[ENUM 03] Filesystem handle count: %u\n", HandleCount);

  for (Index = 0; Index < HandleCount; Index++) {
    FileSystem = NULL;
    Root = NULL;
    File = NULL;

    Print(L"\n[FS %u.1] Handle: %p; calling HandleProtocol...\n",
          Index, Handles[Index]);
    Status = gBS->HandleProtocol(
                    Handles[Index],
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID **)&FileSystem
                    );
    Print(L"[FS %u.2] HandleProtocol returned: %r (0x%lx), interface=%p\n",
          Index, Status, (UINT64)Status, FileSystem);
    if (EFI_ERROR(Status) || (FileSystem == NULL)) {
      continue;
    }

    Print(L"[FS %u.3] Calling OpenVolume...\n", Index);
    Status = FileSystem->OpenVolume(FileSystem, &Root);
    Print(L"[FS %u.4] OpenVolume returned: %r (0x%lx), root=%p\n",
          Index, Status, (UINT64)Status, Root);
    if (EFI_ERROR(Status) || (Root == NULL)) {
      continue;
    }

    Print(L"[FS %u.5] Opening %s...\n",
          Index, WINDOWS_BOOT_MANAGER_PATH);
    Status = Root->Open(
                    Root,
                    &File,
                    WINDOWS_BOOT_MANAGER_PATH,
                    EFI_FILE_MODE_READ,
                    0
                    );
    Print(L"[FS %u.6] File Open returned: %r (0x%lx), file=%p\n",
          Index, Status, (UINT64)Status, File);

    if (!EFI_ERROR(Status) && (File != NULL)) {
      Print(L"[FS %u.7] Boot Manager file found; closing file/root...\n",
            Index);
      File->Close(File);
      Root->Close(Root);
      FoundHandle = Handles[Index];
      Print(L"[FS %u.8] Selected filesystem handle %p\n",
            Index, FoundHandle);
      break;
    }

    Print(L"[FS %u.7] File not found on this handle; closing root.\n",
          Index);
    Root->Close(Root);
  }

  if (Handles != NULL) {
    gBS->FreePool(Handles);
    Handles = NULL;
    Print(L"[ENUM 04] Freed filesystem handle buffer.\n");
  }

  if (FoundHandle == NULL) {
    Print(L"\n[SCAN] Windows Boot Manager was not found on any filesystem.\n");
    goto Done;
  }

  LoadNtfsDriver(ImageHandle, FoundHandle);
  RunLoadProbe(ImageHandle, FoundHandle);

  Print(L"\n[PATH 01] Calling FileDevicePath for selected handle...\n");
  BootManagerPath = FileDevicePath(
                      FoundHandle,
                      WINDOWS_BOOT_MANAGER_PATH
                      );
  Print(L"[PATH 02] FileDevicePath returned: %p\n", BootManagerPath);
  if (BootManagerPath == NULL) {
    Print(L"[PATH 03] Failed to construct device path.\n");
    goto Done;
  }

  Print(L"\n[LOAD 01] About to call LoadImage(FALSE, parent=%p, path=%p, source=NULL, size=0)...\n",
        ImageHandle, BootManagerPath);
  Print(L"[LOAD 02] If the display stops here, the firmware is not returning from LoadImage.\n");

  Status = gBS->LoadImage(
                  FALSE,
                  ImageHandle,
                  BootManagerPath,
                  NULL,
                  0,
                  &WindowsImage
                  );

  Print(L"[LOAD 03] LoadImage RETURNED: %r (0x%lx)\n",
        Status, (UINT64)Status);
  Print(L"[LOAD 04] Loaded image handle: %p\n", WindowsImage);

  if (EFI_ERROR(Status)) {
    Print(L"[LOAD 05] LoadImage failed; StartImage will NOT be called.\n");
    goto Done;
  }

  Print(L"[IMAGE 01] Calling HandleProtocol(LoadedImage) on %p...\n",
        WindowsImage);
  ImageProtocolStatus = gBS->HandleProtocol(
                             WindowsImage,
                             &gEfiLoadedImageProtocolGuid,
                             (VOID **)&LoadedImage
                             );
  Print(L"[IMAGE 02] LoadedImage protocol status: %r (0x%lx), interface=%p\n",
        ImageProtocolStatus, (UINT64)ImageProtocolStatus, LoadedImage);

  if (!EFI_ERROR(ImageProtocolStatus) && (LoadedImage != NULL)) {
    Print(L"[IMAGE 03] ParentHandle=%p DeviceHandle=%p\n",
          LoadedImage->ParentHandle, LoadedImage->DeviceHandle);
    Print(L"[IMAGE 04] ImageBase=%p ImageSize=0x%lx LoadOptionsSize=%u\n",
          LoadedImage->ImageBase, (UINT64)LoadedImage->ImageSize,
          LoadedImage->LoadOptionsSize);
    Print(L"[IMAGE 05] Image loaded successfully; preparing StartImage.\n");
  }

  Print(L"\n[START 01] About to call StartImage(%p)...\n", WindowsImage);
  Print(L"[START 02] If the display stops here, StartImage has not returned.\n");
  StartStatus = gBS->StartImage(
                       WindowsImage,
                       &ExitDataSize,
                       &ExitData
                       );

  Print(L"[START 03] StartImage RETURNED: %r (0x%lx)\n",
        StartStatus, (UINT64)StartStatus);
  Print(L"[START 04] ExitDataSize=%u ExitData=%p\n",
        ExitDataSize, ExitData);

  if ((ExitData != NULL) && (ExitDataSize >= sizeof(CHAR16))) {
    Print(L"[START 05] Child image exit text: %s\n", ExitData);
    gBS->FreePool(ExitData);
    ExitData = NULL;
  }

  Print(L"[IMAGE 06] Calling UnloadImage(%p)...\n", WindowsImage);
  Status = gBS->UnloadImage(WindowsImage);
  Print(L"[IMAGE 07] UnloadImage returned: %r (0x%lx)\n",
        Status, (UINT64)Status);

Done:
  if (ExitData != NULL) {
    gBS->FreePool(ExitData);
  }
  if (BootManagerPath != NULL) {
    gBS->FreePool(BootManagerPath);
  }
  if (Handles != NULL) {
    gBS->FreePool(Handles);
  }

  Print(L"\n[DONE] BootLab finished. No EFI files, BCD, partitions, or NVRAM were intentionally modified.\n");
  Print(L"[DONE] Final application status: EFI_SUCCESS\n");
  return EFI_SUCCESS;
}


