[Rainmeter]
OnRefreshAction=[!WriteKeyValue Variables GPURegKey [DetectGPUinRegistry]][!SetVariable GPURegKey [DetectGPUinRegistry]]

[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


;---- Standard Windows Measures ----

[DetectGPUinRegistry]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DEVICEMAP\VIDEO
RegValue			=\Device\Video[#GPUVideoAdapter]
RegExpSubstitute	=1
Substitute			="\Registry\Machine\":""
UpdateDivider		=-1

[Measure_GPUName]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=#GPURegKey#
RegValue			=HardwareInformation.AdapterString
RegExpSubstitute	=1
Substitute			=#GPUFilterWindows#
UpdateDivider		=3
IfEqualValue		=0
IfEqualAction		=[!SetOption Title MeasureName "Measure_GPUName2"]

[Measure_GPUName2]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=#GPURegKey#
RegValue			=DriverDesc
RegExpSubstitute	=1
Substitute			=#GPUFilterWindows#
UpdateDivider		=3

[Measure_MaxVRAMRaw]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=#GPURegKey#
RegValue			=HardwareInformation.qwMemorySize
UpdateDivider		=-1
IfEqualValue		=0
IfEqualAction		=[!DisableMeasure Measure_VRAMRaw][!DisableMeasure Measure_MaxVRAM][!DisableMeasure Measure_VRAM][!HideMeterGroup GPUVRAM]

[Measure_MaxVRAM]
Measure				=Calc
Formula				=Measure_MaxVRAMRaw/1024/1024/1024
DynamicVariables	=-1

[Measure_VRAMRaw]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=GPU Adapter Memory
Counter				=Dedicated Usage
Index				=0

[Measure_VRAM]
Measure				=Calc
Formula				=[Measure_VRAMRaw:]/1024/1024
DynamicVariables	=1

[Measure_GPUUsage]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=GPU Engine
Counter				=Utilization Percentage
Index				=0

[Measure_GPUUsage2]
Measure				=Calc
Formula				=100-[Measure_GPUUsage:]
MaxValue			=100
MinValue			=0
DynamicVariables	=1


;---- Standard Meter ----

[Info1Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterMid
	Y=(#PHeight#*0.2)
	Text=[Measure_GPUUsage:1] %
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.6)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
	Group=GPUVRAM
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
	Group=GPUVRAM
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_VRAM
	Text=%1 MB
	DynamicVariables=1
	Group=GPUVRAM
	
[Title]
	Meter=String
	MeasureName=Measure_GPUName
	MeterStyle=PText | PTitle
	Text=#GPUNameWin#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#GPUHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_GPUUsage2
UpdateDivider=1
Hidden=#GPUHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#GPUHideGraph#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size