;---- Standard Windows Measures ----

[Measure_Usage]
Measure				=PhysicalMemory

[Measure_Max]
Measure				=PhysicalMemory
Total				=1

[Measure_Top1]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=Process
Counter				=Working Set - Private
Index				=1
UpdateDivider		=20

[Measure_Top2]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=Process
Counter				=Working Set - Private
Index				=2
UpdateDivider		=20

[Measure_Top3]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=Process
Counter				=Working Set - Private
Index				=3
UpdateDivider		=20

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_Usage/Measure_Max)
UpdateDivider		=20

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_Usage/Measure_Max)
UpdateDivider		=20


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=SmoothLeftRoundline
ValueRemainder=100

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=SmoothRightRoundline
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
MouseOverAction=[!ShowMeter ControlBack][!ShowMeter ControlNext]
MouseLeaveAction=[!HideMeter ControlBack][!HideMeter ControlNext]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=perfmon/res


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	MeasureName=Measure_Max
	X=(#CRadius#*1.12)
	Y=(#CRadius#*0.160)
	Text=%1B
	AutoScale=1
	NumOfDecimals=0
	Hidden=#RAMHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#RAMHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#RAMHideRLLabel#

;---- Graph ----

[MeterGraph]
	Meter=Line
	MeasureName=Measure_Usage
	LineCount=1
	MeterStyle=HWiNFOGraphStyle2
	AutoScale=1
	UpdateDivider=10
	
;---- Standard Meter ----

[TotalUsage]
	Meter=String
	MeterStyle=CText | CCenter | CSize1
	Y=(#CRadius#*0.50)
	MeasureName=Measure_Usage
	Text=%1B
	AutoScale=1
	NumOfDecimals=1
	UpdateDivider=20
	
[Process_1Percent]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.17)
	Text=[Measure_Top1:/1048576,0] MB:
[Process_1Name]
	Meter=String
	MeterStyle=CText | CSize5
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top1]
	Clipstring=1
	W=(#CRadius#*0.75)
	
[Process_2Percent]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.31)
	Text=[Measure_Top2:/1048576,0] MB:
[Process_2Name]
	Meter=String
	MeterStyle=CText | CSize6
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top2]
	Clipstring=1
	W=(#CRadius#*0.65)
	
[Process_3Percent]
	Meter=String
	MeterStyle=CText | CSize7
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.43)
	Text=[Measure_Top3:/1048576,0] MB:
[Process_3Name]
	Meter=String
	MeterStyle=CText | CSize7
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top3]
	Clipstring=1
	W=(#CRadius#*0.55)
	
[Title]
	Meter=String
	MeasureName=Measure_RAMName
	MeterStyle=CText | CTitle
	Text=RAM


[ControlBack]
Meter=Image
ImageName=#@#Images\Buttons\BtnPrev.png
ImageTint=#Circle-ButtonColor#
X=(#CRadius#*0.36)
Y=(#CRadius#*1.58)
H=(#CRadius#*0.2)
W=(#CRadius#*0.2)	
DynamicVariables=1
Hidden=1
MouseOverAction=[!SetOption ControlBack ImageTint #Circle-RoundlineFillColor1#][!Update]
MouseLeaveAction=[!SetOption ControlBack ImageTint #Circle-ButtonColor#][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "CPU" "#@#Variables.inc"][!Refresh]

[ControlNext]
Meter=Image
ImageName=#@#Images\Buttons\BtnNext.png
ImageTint=#Circle-ButtonColor#
X=(#CRadius#*1.44)	
Y=(#CRadius#*1.58)
H=(#CRadius#*0.2)		
W=(#CRadius#*0.2)		
DynamicVariables=1
Hidden=1
MouseOverAction=[!SetOption ControlNext ImageTint #Circle-RoundlineFillColor1#][!Update]
MouseLeaveAction=[!SetOption ControlNext ImageTint #Circle-ButtonColor#][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "GPU" "#@#Variables.inc"][!Refresh]


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



