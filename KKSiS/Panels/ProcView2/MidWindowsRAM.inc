[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc

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

[Measure_Top4]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=Process
Counter				=Working Set - Private
Index				=4
UpdateDivider		=20

[Measure_Top5]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=Process
Counter				=Working Set - Private
Index				=5
UpdateDivider		=20


;---- Bar Calculation ----

[SmoothBar]
Measure			=Calc
Formula			=100-100*(Measure_Usage/Measure_Max)
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
	Text=%1B
	AutoScale=1
	NumOfDecimals=1
	UpdateDivider=20
	
[Process_1Percent]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	X=(#PHeight#*0.4)
	Y=(#PHeight#*0.4)
	Text=[Measure_Top1:/1048576,0] MB:
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
	Text=[Measure_Top2:/1048576,0] MB:
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
	Text=[Measure_Top3:/1048576,0] MB:
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
	Text=[Measure_Top4:/1048576,0] MB:
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
	Text=[Measure_Top5:/1048576,0] MB:
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
Text=RAM


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
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "CPU" "#@#Variables.inc"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables ProcView2Format3 "GPU" "#@#Variables.inc"][!Refresh]