;---- Standard Windows Measures ----

[Measure_Usage_Raw]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=IO
Index				=0

[Measure_Usage]
Measure				=Calc
Formula				=[Measure_Usage_Raw:]
UpdateDivider		=1
DynamicVariables	=1
IfCondition			=(Measure_Usage >= 1073741824)
IfTrueAction		=[!SetOption "TotalUsage" "NumOfDecimals" "2"]
IfFalseAction		=[!SetOption "TotalUsage" "NumOfDecimals" "0"]
IfCondition2		=(Measure_Usage > #MaxIO#)
IfTrueAction2		=[!SetVariable MaxIO [Measure_Usage]][!WriteKeyValue Variables MaxIO [Measure_Usage]][!UpdateMeter SmoothLeftRoundline][!UpdateMeter SmoothRightRoundline]

[Measure_Top1_Raw]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=IO
Index				=1
UpdateDivider		=10

[Measure_Top1]
Measure				=Calc
Formula				=[Measure_Top1_Raw:]
UpdateDivider		=1
DynamicVariables	=10
IfCondition			=(Measure_Top1 >= 1073741824)
IfTrueAction		=[!SetOption "Process_1Percent" "NumOfDecimals" "2"]
IfFalseAction		=[!SetOption "Process_1Percent" "NumOfDecimals" "0"]
IfCondition2		=(Measure_Top1 < 1)
IfTrueAction2		=[!HideMeter Process_1Percent][!HideMeter Process_1Name]
IfFalseAction2		=[!ShowMeter Process_1Percent][!ShowMeter Process_1Name]

[Measure_Top2_Raw]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=IO
Index				=2
UpdateDivider		=10

[Measure_Top2]
Measure				=Calc
Formula				=[Measure_Top2_Raw:]
UpdateDivider		=1
DynamicVariables	=10
IfCondition			=(Measure_Top2 >= 1073741824)
IfTrueAction		=[!SetOption "Process_2Percent" "NumOfDecimals" "2"]
IfFalseAction		=[!SetOption "Process_2Percent" "NumOfDecimals" "0"]
IfCondition2		=(Measure_Top2 < 1)
IfTrueAction2		=[!HideMeter Process_2Percent][!HideMeter Process_2Name]
IfFalseAction2		=[!ShowMeter Process_2Percent][!ShowMeter Process_2Name]


[Measure_Top3_Raw]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=IO
Index				=3
UpdateDivider		=10

[Measure_Top3]
Measure				=Calc
Formula				=[Measure_Top3_Raw:]
UpdateDivider		=1
DynamicVariables	=10
IfCondition			=(Measure_Top3 >= 1073741824)
IfTrueAction		=[!SetOption "Process_3Percent" "NumOfDecimals" "2"]
IfFalseAction		=[!SetOption "Process_3Percent" "NumOfDecimals" "0"]
IfCondition2		=(Measure_Top3 < 1)
IfTrueAction2		=[!HideMeter Process_3Percent][!HideMeter Process_3Name]
IfFalseAction2		=[!ShowMeter Process_3Percent][!ShowMeter Process_3Name]

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_Usage/#MaxIO#)
UpdateDivider		=1
AverageSize			=40
DynamicVariables	=1

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_Usage/#MaxIO#)
UpdateDivider		=1
AverageSize			=40
DynamicVariables	=1


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
	AutoScale=1
	
	
;---- Standard Meter ----

[TotalUsage]
	Meter=String
	MeterStyle=CText | CCenter | CSize1
	Y=(#CRadius#*0.50)
	MeasureName=Measure_Usage
	Text=%1B/s
	AutoScale=1
	NumOfDecimals=0
	UpdateDivider=10

[Process_1Percent]
	Meter=String
	MeasureName=Measure_Top1
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.17)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=0
[Process_1Name]
	Meter=String
	MeterStyle=CText | CSize5
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top1_Raw]
	Clipstring=1
	W=(#CRadius#*0.75)
	
[Process_2Percent]
	Meter=String
	MeasureName=Measure_Top2
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.31)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=1
[Process_2Name]
	Meter=String
	MeterStyle=CText | CSize6
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top2_Raw]
	Clipstring=1
	W=(#CRadius#*0.65)
	
[Process_3Percent]
	Meter=String
	MeasureName=Measure_Top3
	MeterStyle=CText | CSize7
	StringAlign=Right
	X=(#CRadius#*0.90)
	Y=(#CRadius#*1.43)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=1
[Process_3Name]
	Meter=String
	MeterStyle=CText | CSize7
	X=(#CRadius#*0.92)
	Y=0r
	Text=[Measure_Top3_Raw]
	Clipstring=1
	W=(#CRadius#*0.55)
	
[Title]
	Meter=String
	MeasureName=Measure_RAMName
	MeterStyle=CText | CTitle
	Text=I/O


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
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "GPU" "#@#Variables.inc"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "CPU" "#@#Variables.inc"][!Refresh]


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



