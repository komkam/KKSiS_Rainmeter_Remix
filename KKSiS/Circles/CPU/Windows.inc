[variables]
@Include6=#@#Windows-Sensors.inc


;---- Standard Windows Measures ----

[Measure_CPUName]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DESCRIPTION\System\CentralProcessor\0
RegValue			=ProcessorNameString
RegExpSubstitute	=1
Substitute			=#CPUFilterWindows#
UpdateDivider		=-1

[Measure_CPUFrequency]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DESCRIPTION\System\CentralProcessor\0
RegValue			=~MHz
UpdateDivider		=-1

[Measure_CPUUsage]
Measure				=CPU
Processor			=0
UpdateDivider		=1

[Measure_CPUUsage2]
Measure				=CPU
Processor			=0
InvertMeasure		=1
UpdateDivider		=1


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=Measure_CPUUsage2
ValueRemainder=100

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=Measure_CPUUsage2
ValueRemainder=100

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
	LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]
	MouseOverAction=[!ShowMeterGroup ProcList]
	MouseLeaveAction=[!HideMeterGroup ProcList]
	
[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=taskmgr


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=100%
	Hidden=#CPUHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#CPUHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=100%
	Hidden=#CPUHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#CPUHideRLLabel#


;---- Graph ----

[Graph Label1]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.31)
	Y=(#CRadius#*0.79)
	Text=CPU Usage
	Hidden=#CPUHideGraph#

[MeterCPUGraph]
	Meter=Line
	MeasureName=Measure_CPUUsage
	LineCount=1
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#CPUHideGraph#


;---- Standard Meter

[Info1Text]
	Meter=String
	MeterStyle=CText | CSize0 | CCenter
	Y=(#CRadius#*(0.4+#CPUHideGraph#*0.2))
	MeasureName=Measure_CPUUsage
	Text=%1 %
	NumOfDecimals=1
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*(1.3-#CPUHideGraph#*0.1))
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_CPUFrequency
	Text=%1 MHz
	NumOfDecimals=0
	DynamicVariables=1

[Title]
	Meter=String
	MeasureName=Measure_CPUName
	MeterStyle=CText | CTitle
	Text=#CPUNameWin#
	Hidden=0





;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size




