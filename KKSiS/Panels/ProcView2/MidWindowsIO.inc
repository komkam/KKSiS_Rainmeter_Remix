[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc

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


[Measure_Top4_Raw]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=IO
Index				=4
UpdateDivider		=10

[Measure_Top4]
Measure				=Calc
Formula				=[Measure_Top4_Raw:]
UpdateDivider		=1
DynamicVariables	=10
IfCondition			=(Measure_Top4 >= 1073741824)
IfTrueAction		=[!SetOption "Process_4Percent" "NumOfDecimals" "2"]
IfFalseAction		=[!SetOption "Process_4Percent" "NumOfDecimals" "0"]
IfCondition2		=(Measure_Top3 < 1)
IfTrueAction2		=[!HideMeter Process_4Percent][!HideMeter Process_4Name]
IfFalseAction2		=[!ShowMeter Process_4Percent][!ShowMeter Process_4Name]


[Measure_Top5_Raw]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=IO
Index				=5
UpdateDivider		=10

[Measure_Top5]
Measure				=Calc
Formula				=[Measure_Top5_Raw:]
UpdateDivider		=1
DynamicVariables	=10
IfCondition			=(Measure_Top5 >= 1073741824)
IfTrueAction		=[!SetOption "Process_5Percent" "NumOfDecimals" "2"]
IfFalseAction		=[!SetOption "Process_5Percent" "NumOfDecimals" "0"]
IfCondition2		=(Measure_Top3 < 1)
IfTrueAction2		=[!HideMeter Process_5Percent][!HideMeter Process_5Name]
IfFalseAction2		=[!ShowMeter Process_5Percent][!ShowMeter Process_5Name]


;---- Bar Calculation ----

[SmoothBar]
Measure			=Calc
Formula			=100-100*(Measure_Usage/#MaxIO#)
MaxValue		=100
MinValue		=0
UpdateDivider	=1
AverageSize		=40


;---- Standard Meter ----

[TotalUsage]
	Meter=String
	MeterStyle=PText | PCenterMid | PSize1
	Y=(#PHeight#*0.10)
	MeasureName=Measure_Usage
	Text=%1B/s
	AutoScale=1
	NumOfDecimals=0
	UpdateDivider=10
	
[Process_1Percent]
	Meter=String
	MeasureName=Measure_Top1
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.4)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=0
[Process_1Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.45)
	Y=0r
	Text=[Measure_Top1_Raw]
	Clipstring=1
	W=(#PHeight#*0.59)
	
[Process_2Percent]
	Meter=String
	MeasureName=Measure_Top2
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.5)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=0
[Process_2Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.45)
	Y=0r
	Text=[Measure_Top2_Raw]
	Clipstring=1
	W=(#PHeight#*0.59)
	
[Process_3Percent]
	Meter=String
	MeasureName=Measure_Top3
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.60)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=0
[Process_3Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.45)
	Y=0r
	Text=[Measure_Top3_Raw]
	Clipstring=1
	W=(#PHeight#*0.59)

[Process_4Percent]
	Meter=String
	MeasureName=Measure_Top4
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.70)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=0
[Process_4Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.45)
	Y=0r
	Text=[Measure_Top4_Raw]
	Clipstring=1
	W=(#PHeight#*0.59)

[Process_5Percent]
	Meter=String
	MeasureName=Measure_Top5
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.80)
	Text=%1B/s:
	AutoScale=1
	NumOfDecimals=0
[Process_5Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.45)
	Y=0r
	Text=[Measure_Top5_Raw]
	Clipstring=1
	W=(#PHeight#*0.59)

	
[Title]
Meter=String
MeterStyle=PText | PTitle
Text=I/O


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#ProcView2HideBar#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=SmoothBar
UpdateDivider=1
Hidden=#ProcView2HideBar#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#ProcView2HideBar#


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

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size

[ControlBack]
Meter=Image
ImageName=#@#Images\Buttons\BtnPrev.png
ImageTint=#Panel-ButtonColor#
X=(#PHeight#*0.05)
Y=(#PHeight#*0.92)
H=(#PHeight#*0.13)
W=(#PHeight#*0.13)	
DynamicVariables=1
Hidden=1
MouseOverAction=[!SetOption ControlBack ImageTint #Panel-BarFillColor1#][!Update]
MouseLeaveAction=[!SetOption ControlBack ImageTint #Panel-ButtonColor#][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "GPU" "#@#Variables.inc"][!Refresh]

[ControlNext]
Meter=Image
ImageName=#@#Images\Buttons\BtnNext.png
ImageTint=#Panel-ButtonColor#
X=(#PHeight#*0.91)	
Y=(#PHeight#*0.92)
H=(#PHeight#*0.13)		
W=(#PHeight#*0.13)		
DynamicVariables=1
Hidden=1
MouseOverAction=[!SetOption ControlNext ImageTint #Panel-BarFillColor1#][!Update]
MouseLeaveAction=[!SetOption ControlNext ImageTint #Panel-ButtonColor#][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "CPU" "#@#Variables.inc"][!Refresh]