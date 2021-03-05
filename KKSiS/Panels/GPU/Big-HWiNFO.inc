[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_GPUName]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-Temp_Id#
HWiNFOSensorInstance=#GPU-Temp_Instance#
HWiNFOEntryId		=#GPU-Temp_EntryId#
HWiNFOType			=SensorName
RegExpSubstitute	=1
Substitute			=#GPUFilterHWiNFO#
UpdateDivider		=-1

[Measure_GPUTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-Temp_Id#
HWiNFOSensorInstance=#GPU-Temp_Instance#
HWiNFOEntryId		=#GPU-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUUsage]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-CoreLoad_Id#
HWiNFOSensorInstance=#GPU-CoreLoad_Instance#
HWiNFOEntryId		=#GPU-CoreLoad_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUPower]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-Power_Id#
HWiNFOSensorInstance=#GPU-Power_Instance#
HWiNFOEntryId		=#GPU-Power_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUClock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-Clock_Id#
HWiNFOSensorInstance=#GPU-Clock_Instance#
HWiNFOEntryId		=#GPU-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_VRAM]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-VRAM_Id#
HWiNFOSensorInstance=#GPU-VRAM_Instance#
HWiNFOEntryId		=#GPU-VRAM_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUFAN1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-FAN1_Id#
HWiNFOSensorInstance=#GPU-FAN1_Instance#
HWiNFOEntryId		=#GPU-FAN1_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_GPUFAN2]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-FAN2_Id#
HWiNFOSensorInstance=#GPU-FAN2_Instance#
HWiNFOEntryId		=#GPU-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1
IfCondition=(Measure_GPUFAN2 > 0)
IfTrueAction=[!SetOption Info4Text Text "%1 | %2"][!SetOption Info4Graph LineCount 2]
IfFalseAction=[!SetOption Info4Text Text "%1 rpm"][!SetOption Info4Graph LineCount 1]


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	X=(#PHeight#*0.16)
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

[Info2Icon]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPUColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.18)r
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
	Y=(#PHeight#*0.18)r
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
	Y=(#PHeight#*0.18)r
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
	Y=(#PHeight#*0.18)r
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
	Y=(#PHeight#*0.18)r
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
	MeterStyle=PText | PTitle90
	Text=#GPUName#


;---- Graph ----

[Info1Graph]
	Meter=Line
	MeasureName=Measure_GPUClock
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	X=(#PHeight#*0.97)
	Y=(#PHeight#*0.06)
	
[Info2Graph]
	Meter=Line
	MeasureName=Measure_VRAM
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	
[Info3Graph]
	Meter=Line
	MeasureName=Measure_GPUPower
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	
[Info4Graph]
	Meter=Line
	MeasureName=Measure_GPUFAN1
	MeasureName2=Measure_GPUFAN2
	LineCount=2
	MeterStyle=GraphStyleBigPanelHWiNFO	

[Info5Graph]
	Meter=Line
	MeasureName=Measure_GPUTemp
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO

[Info6Graph]
	Meter=Line
	MeasureName=Measure_GPUUsage
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size