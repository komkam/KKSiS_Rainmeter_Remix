[Rainmeter]
OnRefreshAction=[!WriteKeyValue Variables GPURegKey [DetectGPUinRegistry]][!SetVariable GPURegKey [DetectGPUinRegistry]]

[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
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
DynamicVariables	=1
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
IfEqualAction		=[!DisableMeasure SmoothLeftRoundline][!DisableMeasure GraphLeftRoundline][!DisableMeasure Measure_VRAM][!DisableMeasure Measure_VRAMRaw][!DisableMeasure Measure_MaxVRAM][!HideMeterGroup GPUVRAM][!ShowMeterGroup GPUUSAGE][!SetOption "Graph Label1" Text "GPU Usage"][!SetOption "Measure-Roundline-Left" MeasureName SmoothRightRoundline]
IfAboveValue		=0
IfAboveAction		=[!ShowMeterGroup GPUVRAM][!HideMeterGroup GPUUSAGE]

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

[GraphLeftRoundline]
Measure=Calc
Formula=100*([Measure_VRAMRaw:]/[Measure_MaxVRAMRaw])
DynamicVariables=1

[GraphRightRoundline]
Measure=Calc
Formula=[Measure_GPUUsage:]
DynamicVariables=1


;---- Standard Meter ----

[Info1Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterBig
	Y=(#PHeight#*0.1)
	Text=[Measure_GPUUsage:1] %
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	X=(#PHeight#*0.65)
	Y=(#PHeight#*0.7)
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
	MeterStyle=PText | PTitle2
	Text=#GPUNameWin#
	DynamicVariables=1

;---- Graph ----

[InfoGraph]
	Meter=Line
	MeasureName=GraphLeftRoundline
	MeasureName2=GraphRightRoundline
	LineCount=2
	MeterStyle=GraphStyleBigPanelWindows
	Group=GPUVRAM
	
[InfoGraph2]
	Meter=Line
	MeasureName=GraphRightRoundline
	LineCount=1
	MeterStyle=GraphStyleBigPanelWindows
	Group=GPUUSAGE
	
[Graph Label1]
	Meter=String
	MeterStyle=PText | PSize9
	StringAlign=Left
	FontColor=#Panel-BarFillColor1#
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.39)
	Text=GPU VRAM

[Graph Label2]
	Meter=String
	MeterStyle=PText | PSize9
	MeasureName=Measure_RightRL_Name
	StringAlign=Right
	FontColor=#Panel-BarFillColor3#
	X=(#PHeight#*2.03)
	Y=(#PHeight#*0.39)
	Text=GPU Usage
	Group=GPUVRAM
	

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size