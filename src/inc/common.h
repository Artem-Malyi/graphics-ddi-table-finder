#pragma once

#define DRIVER_NAME         L"offset-finder"
#define IOCTL_PASS_INFO     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222000
#define MAX_DDI_FUNCTIONS   76 // According to the below listed definitions from winddi.h 

typedef struct _DDI_FUNC_INFO {
    LARGE_INTEGER   pFunction;
    ULONG           ulIndex;
    BOOLEAN         bIsCandidate;
} DDI_FUNC_INFO, *PDDI_FUNC_INFO;

typedef struct _DDI_PFNS {
    ULONG           ulLength;
    DDI_FUNC_INFO   info[MAX_DDI_FUNCTIONS];
} DDI_PFNS, *PDDI_PFNS;

typedef struct _DDI_OFFSET_FINDER_INFO {
    ULONG           ulDCOBJiterations;
    ULONG           ulPDEViterations;
    LARGE_INTEGER   pKernelDcObj; // pointer to DC object in kernel
    DDI_PFNS        ddiPfns;
} DDI_OFFSET_FINDER_INFO, *PDDI_OFFSET_FINDER_INFO;

typedef struct _DDI_FOUND_OFFSETS {
    ULONG           ulDCOBJoffset;
    ULONG           ulPDEVoffset;
} DDI_FOUND_OFFSETS, *PDDI_FOUND_OFFSETS;

#define NOT_FOUND_OFFSET -1

// The definitions below are taken from winddi.h in Windows DDK.
#define INDEX_DrvEnablePDEV                      0L
#define INDEX_DrvCompletePDEV                    1L
#define INDEX_DrvDisablePDEV                     2L
#define INDEX_DrvEnableSurface                   3L
#define INDEX_DrvDisableSurface                  4L
#define INDEX_DrvAssertMode                      5L
#define INDEX_DrvResetPDEV                       7L
#define INDEX_DrvDisableDriver                   8L
#define INDEX_DrvCreateDeviceBitmap             10L
#define INDEX_DrvDeleteDeviceBitmap             11L
#define INDEX_DrvRealizeBrush                   12L
#define INDEX_DrvDitherColor                    13L
#define INDEX_DrvStrokePath                     14L
#define INDEX_DrvFillPath                       15L
#define INDEX_DrvStrokeAndFillPath              16L
#define INDEX_DrvPaint                          17L
#define INDEX_DrvBitBlt                         18L
#define INDEX_DrvCopyBits                       19L
#define INDEX_DrvStretchBlt                     20L
#define INDEX_DrvSetPalette                     22L
#define INDEX_DrvTextOut                        23L
#define INDEX_DrvEscape                         24L
#define INDEX_DrvDrawEscape                     25L
#define INDEX_DrvQueryFont                      26L
#define INDEX_DrvQueryFontTree                  27L
#define INDEX_DrvQueryFontData                  28L
#define INDEX_DrvSetPointerShape                29L
#define INDEX_DrvMovePointer                    30L
#define INDEX_DrvLineTo                         31L
#define INDEX_DrvSendPage                       32L
#define INDEX_DrvStartPage                      33L
#define INDEX_DrvEndDoc                         34L
#define INDEX_DrvStartDoc                       35L
#define INDEX_DrvGetGlyphMode                   37L
#define INDEX_DrvSynchronize                    38L
#define INDEX_DrvSaveScreenBits                 40L
#define INDEX_DrvGetModes                       41L
#define INDEX_DrvFree                           42L
#define INDEX_DrvDestroyFont                    43L
#define INDEX_DrvQueryFontCaps                  44L
#define INDEX_DrvLoadFontFile                   45L
#define INDEX_DrvUnloadFontFile                 46L
#define INDEX_DrvFontManagement                 47L
#define INDEX_DrvQueryTrueTypeTable             48L
#define INDEX_DrvQueryTrueTypeOutline           49L
#define INDEX_DrvGetTrueTypeFile                50L
#define INDEX_DrvQueryFontFile                  51L
#define INDEX_DrvMovePanning                    52L
#define INDEX_DrvQueryAdvanceWidths             53L
#define INDEX_DrvSetPixelFormat                 54L
#define INDEX_DrvDescribePixelFormat            55L
#define INDEX_DrvSwapBuffers                    56L
#define INDEX_DrvStartBanding                   57L
#define INDEX_DrvNextBand                       58L
#define INDEX_DrvGetDirectDrawInfo              59L
#define INDEX_DrvEnableDirectDraw               60L
#define INDEX_DrvDisableDirectDraw              61L
#define INDEX_DrvQuerySpoolType                 62L
#define INDEX_DrvIcmCreateColorTransform        64L
#define INDEX_DrvIcmDeleteColorTransform        65L
#define INDEX_DrvIcmCheckBitmapBits             66L
#define INDEX_DrvIcmSetDeviceGammaRamp          67L
#define INDEX_DrvGradientFill                   68L
#define INDEX_DrvStretchBltROP                  69L
#define INDEX_DrvPlgBlt                         70L
#define INDEX_DrvAlphaBlend                     71L
#define INDEX_DrvSynthesizeFont                 72L
#define INDEX_DrvGetSynthesizedFontFiles        73L
#define INDEX_DrvTransparentBlt                 74L
#define INDEX_DrvQueryPerBandInfo               75L
#define INDEX_DrvQueryDeviceSupport             76L