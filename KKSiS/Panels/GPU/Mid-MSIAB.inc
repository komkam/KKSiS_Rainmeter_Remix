[Rainmeter]
OnRefreshAction=[!WriteKeyValue Variables GPURegKey [DetectGPUinRegistry]][!SetVariable GPURegKey [DetectGPUinRegistry]][!UpdateMeasure Measure_GPUName]

[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#MSIAB-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_GPUName]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
GPUDescriptor		=DisplayName
RegExpSubstitute	=1
Substitute			=#GPUFilterWindows#
UpdateDivider		=-1

[Measure_GPUTemp]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=0
UpdateDivider		=1

[Measure_GPUUsage]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=48
UpdateDivider		=1

[Measure_GPUUsage2]
Measure				=Calc
Formula				=100-Measure_GPUUsage
MaxValue			=100
MinValue			=0
DynamicVariables	=1

[Measure_GPUPower]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=96
UpdateDivider		=1

[Measure_GPUClock]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=32
UpdateDivider		=1

[Measure_VRAM]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=49
UpdateDivider		=1

[Measure_GPUFAN1]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=16
UpdateDivider		=1

[Measure_GPUFAN2]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
SourceId			=18
UpdateDivider		=1
IfCondition=(Measure_GPUFAN2 > 0)
IfTrueAction=[!SetOption Info4Text Text "%1 | %2"]
IfFalseAction=[!SetOption Info4Text Text "%1 rpm"]


;---- Standard Meter ----

[Info1Icon]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	X=(#PHeight#*0.13+#GPUHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.06)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_GPUClock
	Text=%1 MHz
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
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
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_VRAM
	Text=%1 MB
	NumOfDecimals=0
	DynamicVariables=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#GPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_GPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\FAN#GPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\FAN#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_GPUFAN1
	MeasureName2=Measure_GPUFAN2
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#GPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_GPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#GPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#GPUColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_GPUUsage
	Text=%1%
	NumOfDecimals=1
	DynamicVariables=1

[Title]
	Meter=String
	MeasureName=Measure_GPUName
	MeterStyle=PText | PTitle
	Text=#GPUNameMSIAB#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#GPUHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_GPUUsage2
UpdateDivider=1
Hidden=#GPUHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#GPUHideGraph#

[Bar1Marker]
Meter=Shape
Shape=Rectangle (#PHeight#*0.05),(#PHeight#*0.92),(#PHeight#*0.9),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
UpdateDivider=1
DynamicVariables=1
Hidden=#GPUHideGraph#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size