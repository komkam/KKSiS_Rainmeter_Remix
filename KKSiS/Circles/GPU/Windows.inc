[Rainmeter]
OnRefreshAction=[!WriteKeyValue Variables GPURegKey [DetectGPUinRegistry]][!SetVariable GPURegKey [DetectGPUinRegistry]]

[variables]
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
IfEqualAction		=[!DisableMeasure SmoothLeftRoundline][!DisableMeasure GraphLeftRoundline][!DisableMeasure Measure_VRAM][!DisableMeasure Measure_VRAMRaw][!DisableMeasure Measure_MaxVRAM][!HideMeterGroup GPUVRAM][!ShowMeterGroup GPUUSAGE][!SetOption "Graph Label1" Text "GPU Usage"][!SetOption "Measure-Roundline-Left" MeasureName SmoothRightRoundline]
IfAboveValue		=0
IfAboveAction		=[!ShowMeterGroup GPUVRAM][!HideMeterGroup GPUUSAGE]
IfCondition			=(#GPUHideGraph# = 1)
IfTrueAction		=[!HideMeterGroup Graph]

[Measure_MaxVRAM]
Measure				=Calc
Formula				=Measure_MaxVRAMRaw/1024/1024/1024
DynamicVariables	=1
UpdateDivider		=3

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

[SmoothLeftRoundline]
Measure=Calc
Formula=100-100*([Measure_VRAMRaw:]/[Measure_MaxVRAMRaw])
DynamicVariables=1

[SmoothRightRoundline]
Measure=Calc
Formula=100-[Measure_GPUUsage:]
DynamicVariables=1


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=SmoothLeftRoundline
ValueRemainder=100
DynamicVariables=1

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=SmoothRightRoundline
ValueRemainder=100
DynamicVariables=1

[LD-20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-199.3))
[LD-40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-172.3))
[LD-60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-145.3))
[LD-80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-118.3))
[LD+80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-62.7))
[LD+60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-35.7))
[LD+40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-8.7))
[LD+20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(18.3))

[GlossyEffect]
Meter=Shape
MeterStyle=GlossyEffectStyle


;---- Skin Functions ----

[KlickFunctions]
	Meter=Shape
	MeterStyle=KlickFunctionsBG
	MouseOverAction=[!ShowMeterGroup ProcList]
	MouseLeaveAction=[!HideMeterGroup ProcList]

;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeasureName=Measure_MaxVRAM
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=%1GB
	NumOfDecimals=1
	Hidden=#GPUHideRLLabel#
	Group=GPUVRAM

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#GPUHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=100%
	Hidden=#GPUHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#GPUHideRLLabel#


;---- Graph ----

[MeterGPUGraph]
	Meter=Line
	MeasureName=GraphLeftRoundline
	MeasureName2=GraphRightRoundline
	LineCount=2
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#GPUHideGraph#
	Group=GPUVRAM | Graph

[MeterGPUGraph2]
	Meter=Line
	MeasureName=GraphRightRoundline
	LineCount=1
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#GPUHideGraph#
	Group=GPUUSAGE | Graph
	
[Graph Label1]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.30)
	Y=(#CRadius#*0.84)
	Text=GPU VRAM
	Hidden=#GPUHideGraph#
	Group=Graph

[Graph Label2]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_RightRL_Name
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.7)
	Y=(#CRadius#*0.84)
	Text=GPU Usage
	Hidden=#GPUHideGraph#
	Group=GPUVRAM | Graph
	
;---- Standard Meter

[Info1Text]
	Meter=String
	MeterStyle=CText | CSize0 | CCenter
	Y=(#CRadius#*(0.4+#GPUHideGraph#*0.2))
	Text=[Measure_GPUUsage:1]%
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*(1.3-#GPUHideGraph#*0.1))
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
	Group=GPUVRAM
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
	Group=GPUVRAM
[Info2Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_VRAM
	Text=%1 MB
	NumOfDecimals=0
	DynamicVariables=1
	Group=GPUVRAM

[Title]
	Meter=String
	MeasureName=Measure_GPUName
	MeterStyle=CText | CTitle
	Text=#GPUNameWin#
	Hidden=0
	DynamicVariables=1
	


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



