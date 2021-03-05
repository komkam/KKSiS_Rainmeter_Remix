[variables]

;---- Filter ----
CPUFilterWindows			="(?siU)( [0-9]{1,2}-Core Processor)":"" , "Intel\(R\)":"" , "Intel ":"" , "AMD ":"", "Core\(TM\)":"" , "Pentium\(R\)":"" , "Celeron\(R\)":"" , "CPU ":"" , "@ .*GHz":"" , " with .*" : ""
CPUFilterHWiNFO				="^(.*]: )":"" , "(: .*)$":"" , "AMD":"" , "Intel":""
GPUFilterHWiNFO				="^(.*]: )":"" , "(: .*)$":"" , "AMD":"" , "NVIDIA":"" , "GeForce ":"" , "Radeon ":"" , "Radeon® ":""
GPUFilterWindows			="AMD ":"" , "NVIDIA ":"" , "Radeon\(TM\)":"" , "Radeon® ":"" , "Radeon ":"" , "GeForce ":"" , "GeForce":"" , "\(R\)":"" , "Graphics":""
MainboardFilterWindows		=" GAMING":"" , " PHANTOM":"" , "ROG ":"" , " TAICHI":"" , " ULTIMATE":"" , " Phantom":"" , " R1.0":"" , " R2.0":"" , " R3.0":"" , " R4.0":"" , " SLI":"" , " Extreme":"E" , " STEEL LEGEND":""
NetworkFilterWindows		="(2)":"" , "(3)":"" , "(4)":"" , "#2":"" , "#3":"" , "#4":"" , "(R)":"" , "Gigabit ":"" , "Network ":"" , "Ethernet ":"" , "Connection ":"" , "Controller ":"" , "USB ":"" , "Wi-Fi 6 ":"" , "#LANCustomSubstitute#":"" , "#LANCustomSubstitute2#":""
Network2FilterWindows		="(2)":"" , "(3)":"" , "(4)":"" , "#2":"" , "#3":"" , "#4":"" , "(R)":"" , "Gigabit ":"" , "Network ":"" , "Ethernet ":"" , "Connection ":"" , "Controller ":"" , "USB ":"" , "Wi-Fi 6 ":"" , "#LANCustomSubstitute#":"" , "#LANCustomSubstitute2#":""
FritzBoxFilter				="FRITZ!Box ":"FB " , "\(":"" , "\)":"" , "UI":""


;---- General Variables ----

MouseScale					=5
ActiveSkinSetting			=
ActiveSkinSettingNo			=
Circle-Language				=english
Panel-Language				=english
Settings-Language			=english
TempUnit					=C


;---- Panel Style Variables ----

Panel-FontColor				=210,210,210,255
Panel-BarFillStyle			=2
Panel-BarFillColor1			=255,0,0
Panel-BarFillColor2			=0,0,0
Panel-BarFillColor3			=0,210,0
Panel-BarFillArc			=0.52
Panel-BarColor				=0,0,0
Panel-StrokeColor			=80,80,80
Panel-BGColor				=0,0,0,1
Panel-BGShadowColor			=255,255,255
Panel-HideShadow			=0
Panel-HideBGShadow			=0
Panel-ButtonColor			=210,210,210,255
Panel-Frame					=0

Panel-FontColor-CP1			=210,210,210,255
Panel-BarFillStyle-CP1		=2
Panel-BarFillColor1-CP1		=255,0,0
Panel-BarFillColor2-CP1		=0,0,0
Panel-BarFillColor3-CP1		=0,210,0
Panel-BarFillArc-CP1		=0.38
Panel-BarColor-CP1			=0,0,0
Panel-StrokeColor-CP1		=80,80,80
Panel-BGColor-CP1			=0,0,0,1
Panel-BGShadowColor-CP1		=255,255,255
Panel-HideShadow-CP1		=0
Panel-HideBGShadow-CP1		=0
Panel-ButtonColor-CP1		=210,210,210,255
Panel-Frame-CP1				=0

Panel-FontColor-CP2			=210,210,210,255
Panel-BarFillStyle-CP2		=2
Panel-BarFillColor1-CP2		=255,0,0
Panel-BarFillColor2-CP2		=0,0,0
Panel-BarFillColor3-CP2		=0,210,0
Panel-BarFillArc-CP2		=0.38
Panel-BarColor-CP2			=0,0,0
Panel-StrokeColor-CP2		=80,80,80
Panel-BGColor-CP2			=0,0,0,1
Panel-BGShadowColor-CP2		=255,255,255
Panel-HideShadow-CP2		=0
Panel-HideBGShadow-CP2		=0
Panel-ButtonColor-CP2		=210,210,210,255
Panel-Frame-CP2				=0

Panel-FontColor-CP3			=210,210,210,255
Panel-BarFillStyle-CP3		=2
Panel-BarFillColor1-CP3		=255,0,0
Panel-BarFillColor2-CP3		=0,0,0
Panel-BarFillColor3-CP3		=0,210,0
Panel-BarFillArc-CP3		=0.38
Panel-BarColor-CP3			=0,0,0
Panel-StrokeColor-CP3		=80,80,80
Panel-BGColor-CP3			=0,0,0,1
Panel-BGShadowColor-CP3		=255,255,255
Panel-HideShadow-CP3		=0
Panel-HideBGShadow-CP3		=0
Panel-ButtonColor-CP3		=210,210,210,255
Panel-Frame-CP3				=0


;---- Circle Style Variables ----

Circle-FontColor			=210,210,210,255
Circle-RoundlineFillStyle	=3
Circle-RoundlineFillColor1	=255,0,0
Circle-RoundlineFillColor2	=255,255,0
Circle-RoundlineFillColor3	=0,255,0
Circle-RoundlineFillArc		=0.52
Circle-BarColor				=10,10,10
Circle-DividerColor			=70,70,70
Circle-BGColor				=0,0,0,1
Circle-BGShadowColor		=0,0,0
Circle-HideBGShadow			=0
Circle-HideRLShadow			=0
Circle-ButtonColor			=30,30,30,255
Circle-RLShadowColor		=0,0,0
Circle-GlossyEffect			=0

Circle-FontColor-CP1		=210,210,210,255
Circle-RoundlineFillStyle-CP1=3
Circle-RoundlineFillColor1-CP1=255,0,0
Circle-RoundlineFillColor2-CP1=255,255,0
Circle-RoundlineFillColor3-CP1=0,255,0
Circle-RoundlineFillArc-CP1	=0.52
Circle-BarColor-CP1			=0,0,0
Circle-DividerColor-CP1		=80,80,80
Circle-BGColor-CP1			=0,0,0,1
Circle-BGShadowColor-CP1	=0,0,0
Circle-HideBGShadow-CP1		=0
Circle-HideRLShadow-CP1		=0
Circle-ButtonColor-CP1		=30,30,30,255
Circle-RLShadowColor-CP1	=0,0,0
Circle-GlossyEffect-CP1		=0

Circle-FontColor-CP2		=210,210,210,255
Circle-RoundlineFillStyle-CP2=2
Circle-RoundlineFillColor1-CP2=255,0,0
Circle-RoundlineFillColor2-CP2=89,193,228
Circle-RoundlineFillColor3-CP2=0,210,0
Circle-RoundlineFillArc-CP2	=0.60
Circle-BarColor-CP2			=0,0,0
Circle-DividerColor-CP2		=80,80,80
Circle-BGColor-CP2			=0,0,0,1
Circle-BGShadowColor-CP2	=255,255,255
Circle-HideBGShadow-CP2		=0
Circle-HideRLShadow-CP2		=1
Circle-ButtonColor-CP2		=210,210,210,255
Circle-RLShadowColor-CP2	=255,255,255
Circle-GlossyEffect-CP2		=0

Circle-FontColor-CP3		=210,210,210,255
Circle-RoundlineFillStyle-CP3=2
Circle-RoundlineFillColor1-CP3=255,0,0
Circle-RoundlineFillColor2-CP3=89,193,228
Circle-RoundlineFillColor3-CP3=0,210,0
Circle-RoundlineFillArc-CP3	=0.60
Circle-BarColor-CP3			=0,0,0
Circle-DividerColor-CP3		=80,80,80
Circle-BGColor-CP3			=0,0,0,1
Circle-BGShadowColor-CP3	=255,255,255
Circle-HideBGShadow-CP3		=0
Circle-HideRLShadow-CP3		=1
Circle-ButtonColor-CP3		=210,210,210,255
Circle-RLShadowColor-CP3	=255,255,255
Circle-GlossyEffect-CP3		=0


;---- Skin Variables ----

;---- CPU Variables ----
Panel-CPUSize				=Mid
CPUFormat					=HWiNFO
CPUFormat2					=
CPUHideWindows				=1
CPUHideHWiNFO				=0
CPUHideMSIAB				=1
CPUHideGraph				=0
CPUHideRLLabel				=0
CPUColoredIcons				=1	

;---- CPU2 Variables ----
Panel-CPU2Size				=Big
CPU2Format					=HWiNFO
CPU2Format2					=
CPU2HideGraph				=0
CPU2HideRLLabel				=0
CPU2ColoredIcons			=1	

;---- Process Viewer Variables ----
Panel-ProcViewSize			=Mid
ProcViewFormat				=Windows
ProcViewFormat2				=
ProcViewFormat3				=CPU
ProcViewHideBar				=0

;---- Process Viewer 2 Variables ----
Panel-ProcView2Size			=Mid
ProcView2Format				=Windows
ProcView2Format2			=
ProcView2Format3			=GPU
ProcView2HideBar			=0

;---- GPU Variables ----
Panel-GPUSize				=Small
GPUFormat					=HWiNFO
GPUFormat2					=
GPUHideWindows				=1
GPUHideHWiNFO				=0
GPUHideMSIAB				=1
GPUHideGraph				=0
GPUHideRLLabel				=0
GPUColoredIcons				=1

;---- GPU2 Variables ----
Panel-GPU2Size				=Mid
GPU2Format					=HWiNFO
GPU2Format2					=
GPU2HideHWiNFO				=0
GPU2HideMSIAB				=1
GPU2HideGraph				=0
GPU2HideRLLabel				=0
GPU2ColoredIcons			=1	

;---- FPSView Variables ----
Panel-FPSViewSize			=Small
FPSViewFormat				=HWiNFO
FPSViewFormat2				=
FPSViewHideHWiNFO			=1
FPSViewHideMSIAB			=0
FPSViewHideRLLabel			=0
FPSViewColoredIcons			=1
FPSViewHideAVGFPS			=0
FPSViewHideFrametimes		=0
FPSViewHideDisplayRes		=0
FPSViewDisplayID			=1
FPSViewMaxFPS				=144
FPSViewName					=FPS

;---- RAM Variables ----
Panel-RAMSize				=Big
RAMFormat					=HWiNFO
RAMFormat2					=
RAMHideWindows				=1
RAMHideHWiNFO				=0
RAMHideGraph				=0
RAMHideRLLabel				=0
RAMColoredIcons				=1	
RAMShowPercentage			=0
RAMShowFreeSpace			=0
RAMShowRAMonly				=0
RAMShowTemp					=0

;---- Mainboard Variables ----
Panel-MainboardSize			=Mid
MainboardFormat				=HWiNFO
MainboardFormat2			=
MainboardAllFansRL			=0
MainboardHideSensor			=1
MainboardHideBIOS			=1
MainboardHideGraph			=0
MainboardHideRLLabel		=0
MainboardColoredIcons		=1

;---- Liquid Variables ----
Panel-LiquidSize			=Mid
MainboardFormat				=
MainboardFormat2			=
LiquidHideGraph				=0
LiquidHideRLLabel			=0
LiquidColoredIcons			=1

;---- Wireless Variables ----
Panel-WiFiSize				=Small
WiFiFormat					=Windows
WiFiFormat2					=
WiFiHideQuality				=0
WiFiHideSSID				=1
WiFiColoredIcons			=1
WiFiAdapterIndex			=2

;---- Network Variables ----
Panel-NetworkSize			=Mid
NetworkFormat				=Windows
NetworkFormat2				=
NetworkFormat3				=2
NetworkColoredIcons			=1
NetworkHideRLLabel			=0
NetworkHideGraph1			=0
NetworkHideGraph2			=0
NetworkHideBar				=0

;---- Network2 Variables ----
Panel-Network2Size			=Mid
Network2Format				=Windows
Network2Format2				=
Network2Format3				=2
Network2ColoredIcons		=1
Network2HideRLLabel			=0
Network2HideGraph1			=0
Network2HideGraph2			=0
Network2HideBar				=0

;---- Fritz!Box Variables ----
Panel-FritzBoxsize			=Mid
FritzBoxFormat				=Windows
FritzBoxFormat2				=
FritzBoxFormat3				=DSL
FritzBoxHideRLLabel			=0
FritzBoxColor				=1
FritzBoxColoredIcons		=1	
FritzBoxDSLoverWAN			=0

;---- DualDrive Variables ----
Panel-DualDrivesize			=Mid
DualDriveFormat				=HWiNFO
DualDriveFormat2			=
DualDriveSSD				=1
DualDriveDiskALetter		=C
DualDriveDiskBLetter		=D
DualDriveHideWindows		=1
DualDriveHideHWiNFO			=0
DualDriveHideGraph			=0
DualDriveHideRLLabel		=0
DualDriveColoredIcons		=1	
DualDriveShowPercentage		=0
DualDriveShowFreeSpace		=0

;---- DualDrive2 Variables ----
Panel-DualDrive2size		=Mid
DualDrive2Format			=Windows
DualDrive2Format2			=
DualDrive2SSD				=1
DualDrive2DiskALetter		=E
DualDrive2DiskBLetter		=F
DualDrive2HideWindows		=1
DualDrive2HideHWiNFO		=0
DualDrive2HideGraph			=0
DualDrive2HideRLLabel		=0
DualDrive2ColoredIcons		=1	
DualDrive2ShowPercentage	=0
DualDrive2ShowFreeSpace		=0

;---- Drive1 Variables ----
Panel-Drive1size			=Small
Drive1Format				=HWiNFO
Drive1Format2				=
Drive1SSD					=1
Drive1Letter				=C
Drive1HideWindows			=1
Drive1HideHWiNFO			=0
Drive1HideGraph				=0
Drive1HideRLLabel			=0
Drive1ColoredIcons			=1	
Drive1ShowPercentage		=1
Drive1ShowFreeSpace			=0
Drive1ShowUsageinLeftRL		=1
Drive1ShowUsageinRightRL	=0

;---- Drive2 Variables ----
Panel-Drive2size			=Mid
Drive2Format				=HWiNFO
Drive2Format2				=
Drive2SSD					=1
Drive2Letter				=D
Drive2HideWindows			=1
Drive2HideHWiNFO			=0
Drive2HideGraph				=0
Drive2HideRLLabel			=0
Drive2ColoredIcons			=1	
Drive2ShowPercentage		=1
Drive2ShowFreeSpace			=0
Drive2ShowUsageinLeftRL		=1
Drive2ShowUsageinRightRL	=0

;---- Drive3 Variables ----
Panel-Drive3size			=Mid
Drive3Format				=HWiNFO
Drive3Format2				=
Drive3SSD					=1
Drive3Letter				=E
Drive3HideWindows			=1
Drive3HideHWiNFO			=0
Drive3HideGraph				=0
Drive3HideRLLabel			=0
Drive3ColoredIcons			=1	
Drive3ShowPercentage		=1
Drive3ShowFreeSpace			=0
Drive3ShowUsageinLeftRL		=1
Drive3ShowUsageinRightRL	=0

;---- Drive4 Variables ----
Panel-Drive4size			=Mid
Drive4Format				=Windows
Drive4Format2				=
Drive4SSD					=1
Drive4Letter				=F
Drive4HideWindows			=0
Drive4HideHWiNFO			=1
Drive4HideGraph				=0
Drive4HideRLLabel			=0
Drive4ColoredIcons			=1	
Drive4ShowPercentage		=0
Drive4ShowFreeSpace			=0
Drive4ShowUsageinLeftRL		=0
Drive4ShowUsageinRightRL	=0

;---- Drive5 Variables ----
Panel-Drive5size			=Mid
Drive5Format				=Windows
Drive5Format2				=
Drive5SSD					=1
Drive5Letter				=G
Drive5HideWindows			=0
Drive5HideHWiNFO			=1
Drive5HideGraph				=0
Drive5HideRLLabel			=0
Drive5ColoredIcons			=1	
Drive5ShowPercentage		=0
Drive5ShowFreeSpace			=0
Drive5ShowUsageinLeftRL		=0
Drive5ShowUsageinRightRL	=0

;---- Drive6 Variables ----
Panel-Drive6size			=Mid
Drive6Format				=Windows
Drive6Format2				=
Drive6SSD					=1
Drive6Letter				=H
Drive6HideWindows			=0
Drive6HideHWiNFO			=1
Drive6HideGraph				=0
Drive6HideRLLabel			=0
Drive6ColoredIcons			=1	
Drive6ShowPercentage		=0
Drive6ShowFreeSpace			=0
Drive6ShowUsageinLeftRL		=0
Drive6ShowUsageinRightRL	=0

;---- Drive7 Variables ----
Panel-Drive7size			=Mid
Drive7Format				=HWiNFO
Drive7Format2				=
Drive7SSD					=0
Drive7Letter				=I
Drive7HideWindows			=0
Drive7HideHWiNFO			=1
Drive7HideGraph				=0
Drive7HideRLLabel			=0
Drive7ColoredIcons			=1	
Drive7ShowPercentage		=0
Drive7ShowFreeSpace			=0
Drive7ShowUsageinLeftRL		=0
Drive7ShowUsageinRightRL	=0

;---- Drive8 Variables ----
Panel-Drive8size			=Mid
Drive8Format				=Windows
Drive8Format2				=
Drive8SSD					=0
Drive8Letter				=J
Drive8HideWindows			=0
Drive8HideHWiNFO			=1
Drive8HideGraph				=0
Drive8HideRLLabel			=0
Drive8ColoredIcons			=1	
Drive8ShowPercentage		=0
Drive8ShowFreeSpace			=0
Drive8ShowUsageinLeftRL		=0
Drive8ShowUsageinRightRL	=0

;---- Power Variables ----
Panel-PowerSize				=Small
PowerFormat					=Windows
PowerFormat2				=
PowerHideBar				=0
PowerHideStatus				=0
PowerColoredIcons			=1
PowerHideTitle				=0

;---- Trash Variables ----
Panel-TRSize				=Mid
TrashFormat					=Windows
TrashFormat2				=
TRMaxSize					=2000
TRBinType					=1
Panel-TRColored				=0
Circle-TRColored			=0

;---- Time Variables ----
Panel-TISize				=Big
TimeFormat					=Windows
TimeFormat2					=
Circle-TIFormat				=24H
Panel-TIFormat				=24H
TIShowColoredWeekday		=1
TIHideSeconds				=0
TIShowCWIsoFormat			=1
LeadingZeroes				=0
StartOnMonday				=1

;---- Webradio Variables ----
Panel-WRSize				=Mid
WebradioFormat				=Windows
WebradioFormat2				=
WRAudioBarFormat			=3
WRActive					=0
WRInactive					=1
WRHideVolume				=0
WRShowColoredBtnFrame		=1

;---- Volume Variables ----
Panel-VolumeSize			=Mid
VolumeFormat				=Windows
VolumeFormat2				=
VolumeHideVol				=0
VolumeHideOutput			=0
VolumeColoredIcons			=1

LastSettingsPage=GPU2-Settings.ini
LiquidFormat=HWiNFO
LiquidFormat2=
