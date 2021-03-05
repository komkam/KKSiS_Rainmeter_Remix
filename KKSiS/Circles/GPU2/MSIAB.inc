[Rainmeter]

[variables]
@Include6=#@#MSIAB-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_GPUName]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
GPUDescriptor		=DisplayName
RegExpSubstitute	=1
Substitute			=#GPUFilterWindows#
UpdateDivider		=-1

[Measure_GPUTemp]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=0
UpdateDivider		=1

[Measure_GPUUsage]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=48
UpdateDivider		=1

[Measure_GPUPower]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=96
UpdateDivider		=1

[Measure_GPUClock]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=32
UpdateDivider		=1

[Measure_VRAM]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=49
UpdateDivider		=1

[Measure_GPUFAN1]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=16
UpdateDivider		=1

[Measure_GPUFAN2]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=18
UpdateDivider		=1
IfCondition=(Measure_GPUFAN2 > 0)
IfTrueAction=[!SetOption Info4aText Text "%1rpm"][!SetOption Info4bText Text "%1rpm"]
IfFalseAction=[!SetOption Info4aText Text "%1"][!SetOption Info4bText Text "rpm"]


;---- Roundline Left Measures ----

[Measure_LeftRL_Value]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=#GPU2_RLLeft_ID#
UpdateDivider		=1

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_LeftRL_Value-#GPU2_RLLeft_MinValue#+0.1)/(#GPU2_RLLeft_MaxValue#-#GPU2_RLLeft_MinValue#)
UpdateDivider		=1


;---- Roundline Right Measures ----

[Measure_RightRL_Value]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=1
SourceId			=#GPU2_RLRight_ID#
UpdateDivider		=1

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_RightRL_Value-#GPU2_RLRight_MinValue#+0.1)/(#GPU2_RLRight_MaxValue#-#GPU2_RLRight_MinValue#)
AverageSize			=2
UpdateDivider		=1


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


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=#GPU2_RLLeft_MaxValue#[#SensorUnit[#GPU2_RLLeft_ID]]
	Hidden=#GPU2HideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=#GPU2_RLLeft_MinValue#
	Hidden=#GPU2HideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=#GPU2_RLRight_MaxValue#[#SensorUnit[#GPU2_RLRight_ID]]
	Hidden=#GPU2HideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=#GPU2_RLRight_MinValue#
	Hidden=#GPU2HideRLLabel#


;---- Graph ----

[Graph Label1]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.45)
	Y=(#CRadius#*1.4)
	Text=[#SensorName[#GPU2_RLLeft_ID]]
	Hidden=#GPU2HideGraph#

[Graph Label2]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.55)
	Y=(#CRadius#*1.4)
	Text=[#SensorName[#GPU2_RLRight_ID]]
	Hidden=#GPU2HideGraph#

[MeterGPUGraph]
	Meter=Line
	MeasureName=Measure_LeftRL_Value
	MeasureName2=Measure_RightRL_Value
	LineCount=2
	MeterStyle=HWiNFOGraphStyle
	Hidden=#GPU2HideGraph#


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPU2ColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*0.4)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPU2ColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_GPUClock
	Text=%1 MHz
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPU2ColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#GPU2HideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\RAM#GPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPU2ColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_VRAM
	Text=%1 MB
	NumOfDecimals=0
	DynamicVariables=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#GPU2ColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#GPU2HideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#GPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPU2ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_GPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\FAN#GPU2ColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#GPU2HideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\FAN#GPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPU2ColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_GPUFAN1
	MeasureName2=Measure_GPUFAN2
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#GPU2ColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#GPU2HideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#GPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPU2ColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_GPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#GPU2ColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#GPU2HideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#GPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPU2ColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_GPUUsage
	Text=%1%
	NumOfDecimals=1
	DynamicVariables=1
	
[Title]
	Meter=String
	MeasureName=Measure_GPUName
	MeterStyle=CText | CTitle
	Text=#GPU2NameMSIAB#
	Hidden=0


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



