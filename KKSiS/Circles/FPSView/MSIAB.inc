[variables]
@Include6=#@#MSIAB-Sensors.inc


;---- Standard MSIAB Measures ----

[Measure_FPS]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
DataSource			=Framerate
;SourceId			=80
IfEqualValue		=0
IfEqualAction		=[!HideMeterGroup GameON][!ShowMeterGroup GameOFF]
IfAboveValue		=0
IfAboveAction		=[!HideMeterGroup GameOFF][!ShowMeterGroup GameON][!HideMeter Info6IconB]
IfCondition			=(#FPSViewHideAVGFPS# = 1)
IfTrueAction		=[!HideMeterGroup AVGFPS][!SetOption Info1Text Y "(#CRadius#*0.35)"]
IfCondition2		=(#FPSViewHideFrametimes# = 1)
IfTrueAction2		=[!HideMeterGroup FRMTimes][!SetOption MeterFPSViewGraph LineCount 1]
IfCondition3		=(Measure_FPS = 0) && (#FPSViewColoredIcons# = 0)
IfTrueAction3		=[!ShowMeter Info6IconB]
IfConditionMode		=1
UpdateDivider		=10


[Measure_MinFPS]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
DataSource			=Framerate Min
;SourceId			=82
UpdateDivider		=10

[Measure_MaxFPS]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
DataSource			=Framerate Max
;SourceId			=84
UpdateDivider		=10

[Measure_AvgFPS]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
DataSource			=Framerate Avg
;SourceId			=83
UpdateDivider		=10

[Measure_Frametime]
Measure				=Plugin
Plugin				=MSIAfterburner
GPU					=0
DataSource			=Frametime
;SourceId			=81
UpdateDivider		=10

[Measure_FPSRoundline]
Measure				=Calc
Formula				=#FPSViewMaxFPS#-0.1-Measure_FPS
AverageSize			=20
UpdateDivider		=1


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=Measure_FPSRoundline
ValueRemainder=#FPSViewMaxFPS#

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=Measure_FPSRoundline
ValueRemainder=#FPSViewMaxFPS#

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
	Text=#FPSViewMaxFPS#
	Hidden=#FPSViewHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#FPSViewHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=FPS
	Hidden=#FPSViewHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#FPSViewHideRLLabel#


;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.32)
	Y=(#CRadius#*0.85)
	Text=Framerate (FPS)
	Group=GameON

[GraphLabel2]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.68)
	Y=(#CRadius#*0.85)
	Text=Frametime (ms)
	Group=GameON | FRMTimes
	
[MeterFPSViewGraph]
	Meter=Line
	MeasureName=Measure_FPS
	MeasureName2=Measure_Frametime
	LineCount=2
	MeterStyle=HWiNFOGraphStyle2
	H=(#CRadius#*0.6)
	Group=GameON
	UpdateDivider=5
	Container=MeterFPSViewGraphContainer

[MeterFPSViewGraphContainer]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.3),(#CRadius#*0.3),(#CRadius#*1.4),(#CRadius#*1.4),(#CRadius#*0.7) | StrokeWidth 0 | Fill Color 0,0,0
	DynamicVariables=1
	
;---- Standard Meter ----

	
[Info1Text]
	Meter=String
	MeterStyle=CText | CCenter | CSize0
	Y=(#CRadius#*0.3)
	MeasureName=Measure_FPS
	Text=%1
	NumOfDecimals=0
	AutoScale=0
	Group=GameON

[Info2Text]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=left
	Y=(#CRadius#*0.72)
	X=(#CRadius#*0.35)
	MeasureName=Measure_MinFPS
	Text=Min: %1
	Group=GameON | AVGFPS
	
[Info3Text]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=center
	Y=(#CRadius#*0.72)
	X=#CRadius#
	MeasureName=Measure_AvgFPS
	Text=Avg: %1
	Group=GameON | AVGFPS

[Info4Text]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=right
	Y=(#CRadius#*0.72)
	X=(#CRadius#*1.65)
	MeasureName=Measure_MaxFPS
	Text=Max: %1
	Group=GameON | AVGFPS
	
[Info5Text]
	Meter=String
	MeterStyle=CText | CCenter | CSize6
	Y=(#CRadius#*1.45)
	MeasureName=Measure_Frametime
	Text=Frametime: %1 ms
	Group=GameON | FRMTimes

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	X=(#CRadius#*0.55)
	Y=(#CRadius#*0.55)
	W=(#CRadius#*0.9)
	H=(#CRadius#*0.9)
	DynamicVariables=1
	Group=GameOFF
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.9)
	H=(#CRadius#*0.9)
	Hidden=#FPSViewColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=CText | CCenter | CSize6
	X=#CRadius#
	Y=(#CRadius#*0.5)
	Text=2D Mode
	Group=GameOFF

[Title]
	Meter=String
	MeterStyle=CText | CTitle
	Text=#FPSViewName#
	Hidden=0


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size