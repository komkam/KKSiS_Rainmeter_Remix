[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc

[Measure_Usage]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=GPU
Index				=0

[Measure_Top1]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=GPU
Index				=1
IfCondition			=(Measure_Top1 >= 0.01)
IfTrueAction		=[!ShowMeter Process_1Percent][!ShowMeter Process_1Name]
IfFalseAction		=[!HideMeter Process_1Percent][!HideMeter Process_1Name]
UpdateDivider		=20

[Measure_Top2]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=GPU
Index				=2
IfCondition			=(Measure_Top2 >= 0.01)
IfTrueAction		=[!ShowMeter Process_2Percent][!ShowMeter Process_2Name]
IfFalseAction		=[!HideMeter Process_2Percent][!HideMeter Process_2Name]
UpdateDivider		=20

[Measure_Top3]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=GPU
Index				=3
IfCondition			=(Measure_Top3 >= 0.01)
IfTrueAction		=[!ShowMeter Process_3Percent][!ShowMeter Process_3Name]
IfFalseAction		=[!HideMeter Process_3Percent][!HideMeter Process_3Name]
UpdateDivider		=20

[Measure_Top4]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=GPU
Index				=4
IfCondition			=(Measure_Top4 >= 0.01)
IfTrueAction		=[!ShowMeter Process_4Percent][!ShowMeter Process_4Name]
IfFalseAction		=[!HideMeter Process_4Percent][!HideMeter Process_4Name]
UpdateDivider		=20

[Measure_Top5]
Measure				=Plugin
Plugin				=UsageMonitor
Alias				=GPU
Index				=5
IfCondition			=(Measure_Top5 >= 0.01)
IfTrueAction		=[!ShowMeter Process_5Percent][!ShowMeter Process_5Name]
IfFalseAction		=[!HideMeter Process_5Percent][!HideMeter Process_5Name]
UpdateDivider		=20


;---- Bar Calculation ----

[SmoothBar]
Measure			=Calc
Formula			=100-Measure_Usage
MaxValue		=100
MinValue		=0
UpdateDivider	=1
AverageSize		=40


;---- Standard Meter ----

[TotalUsage]
	Meter=String
	MeterStyle=PText | PCenterMid | PSize1
	Y=(#PHeight#*0.10)
	Text=[Measure_Usage:2]%
	UpdateDivider=10
	
[Process_1Percent]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.4)
	Y=(#PHeight#*0.4)
	Text=[Measure_Top1:2]%:
[Process_1Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.42)
	Y=0r
	Text=[Measure_Top1]
	Clipstring=1
	W=(#PHeight#*0.59)
	
[Process_2Percent]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.4)
	Y=(#PHeight#*0.5)
	Text=[Measure_Top2:2]%:
[Process_2Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.42)
	Y=0r
	Text=[Measure_Top2]
	Clipstring=1
	W=(#PHeight#*0.59)
	
[Process_3Percent]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.40)
	Y=(#PHeight#*0.60)
	Text=[Measure_Top3:2]%:
[Process_3Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.42)
	Y=0r
	Text=[Measure_Top3]
	Clipstring=1
	W=(#PHeight#*0.59)

[Process_4Percent]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.40)
	Y=(#PHeight#*0.70)
	Text=[Measure_Top4:2]%:
[Process_4Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.42)
	Y=0r
	Text=[Measure_Top4]
	Clipstring=1
	W=(#PHeight#*0.59)

[Process_5Percent]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.40)
	Y=(#PHeight#*0.80)
	Text=[Measure_Top5:2]%:
[Process_5Name]
	Meter=String
	MeterStyle=PText | PSize6
	X=(#PHeight#*0.42)
	Y=0r
	Text=[Measure_Top5]
	Clipstring=1
	W=(#PHeight#*0.59)

	
[Title]
Meter=String
MeterStyle=PText | PTitle
Text=GPU


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#ProcViewHideBar#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=SmoothBar
UpdateDivider=1
Hidden=#ProcViewHideBar#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#ProcViewHideBar#


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
LeftMouseUpAction=[!WriteKeyValue Variables ProcViewFormat3 "RAM" "#@#Variables.inc"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables ProcViewFormat3 "IO" "#@#Variables.inc"][!Refresh]