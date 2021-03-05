[Rainmeter]
OnRefreshAction=[!WriteKeyValue Variables GPURegKey [DetectGPUinRegistry]][!SetVariable GPURegKey [DetectGPUinRegistry]]

[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
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
RegValue			=DriverDesc
RegExpSubstitute	=1
Substitute			=#GPUFilterWindows#
UpdateDivider		=3

[Measure_VRAMRaw]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=GPU Adapter Memory
Counter				=Dedicated Usage
Index				=0
DynamicVariables	=1
UpdateDivider		=1
IfEqualValue		=0
IfEqualAction		=[!SetOption Info1Text Text "#GPUNameWin#"][!SetOption Info1Text MeasureName "Measure_GPUName"]
IfAboveValue		=0
IfAboveAction		=[!SetOption Info1Text Text "%1 MB"][!SetOption Info1Text MeasureName "Measure_VRAM"]
IfConditionMode		=1

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


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_VRAM
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	W=(#PHeight#*0.74)
	Clipstring=1
	Text=%1 MB
	DynamicVariables=1

[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	Text=[Measure_GPUUsage:1] %
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	NumOfDecimals=1
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size