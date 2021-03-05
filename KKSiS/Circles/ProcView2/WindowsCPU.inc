;---- Standard Windows Measures ----

[Measure_Usage]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=0

[Measure_Top1]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=1
IfCondition			=(Measure_Top1 >= 0.01)
IfTrueAction		=[!ShowMeter Process_1Percent][!ShowMeter Process_1Name]
IfFalseAction		=[!HideMeter Process_1Percent][!HideMeter Process_1Name]
UpdateDivider		=20

[Measure_Top2]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=2
IfCondition			=(Measure_Top2 >= 0.01)
IfTrueAction		=[!ShowMeter Process_2Percent][!ShowMeter Process_2Name]
IfFalseAction		=[!HideMeter Process_2Percent][!HideMeter Process_2Name]
UpdateDivider		=20

[Measure_Top3]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=CPU
Index				=3
IfCondition			=(Measure_Top3 >= 0.01)
IfTrueAction		=[!ShowMeter Process_3Percent][!ShowMeter Process_3Name]
IfFalseAction		=[!HideMeter Process_3Percent][!HideMeter Process_3Name]
UpdateDivider		=20

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-(Measure_Usage+0.1)
UpdateDivider		=1
AverageSize			=40

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-Measure_Usage
UpdateDivider		=1
AverageSize			=40


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
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=100
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

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=%
	Hidden=#RAMHideRLLabel#

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
	AutoScale=0
	MaxValue=100
	MinValue=0
	
	
;---- Standard Meter ----

[TotalUsage]
	Meter=String
	MeterStyle=CText | CCenter | CSize1
	Y=(#CRadius#*0.50)
	Text=[Measure_Usage:2]%
	NumOfDecimals=1
	UpdateDivider=10
	
[Process_1Percent]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.17)
	Text=[Measure_Top1:2]%:
	Hidden=1
[Process_1Name]
	Meter=String
	MeterStyle=CText | CSize5
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top1]
	Clipstring=1
	W=(#CRadius#*0.75)
	Hidden=1
	
[Process_2Percent]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.31)
	Text=[Measure_Top2:2]%:
	Hidden=1
[Process_2Name]
	Meter=String
	MeterStyle=CText | CSize6
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top2]
	Clipstring=1
	W=(#CRadius#*0.65)
	Hidden=1
	
[Process_3Percent]
	Meter=String
	MeterStyle=CText | CSize7
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.43)
	Text=[Measure_Top3:2]%:
	Hidden=1
[Process_3Name]
	Meter=String
	MeterStyle=CText | CSize7
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top3]
	Clipstring=1
	W=(#CRadius#*0.55)
	Hidden=1
	
[Title]
	Meter=String
	MeterStyle=CText | CTitle
	Text=CPU


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
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "IO" "#@#Variables.inc"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "RAM" "#@#Variables.inc"][!Refresh]


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



