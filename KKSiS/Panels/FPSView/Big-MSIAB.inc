[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
;---- Sensors ----
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
IfTrueAction		=[!HideMeterGroup AVGFPS]
IfCondition2		=(#FPSViewHideFrametimes# = 1)
IfTrueAction2		=[!HideMeterGroup FRMTimes][!SetOption MeterFPSViewGraph W "(#PHeight#*1.985)"][!ShowMeter Title][!SetOption Info4Text X "(#PHeight#*1.038)"]
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


;---- Standard Meter ----

[Info1Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.05)
	MeasureName=Measure_MinFPS
	Text=Min: %1
	Group=GameON | AVGFPS

[Info2Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.15)
	MeasureName=Measure_AvgFPS
	Text=Avg: %1
	Group=GameON | AVGFPS

[Info3Text]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=left
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.25)
	MeasureName=Measure_MaxFPS
	Text=Max: %1
	Group=GameON | AVGFPS
	
[Info4Text]
	Meter=String
	MeterStyle=PText | PSize0
	StringAlign=Center
	X=(#PHeight#*0.538)
	Y=(#PHeight#*0.06)
	MeasureName=Measure_FPS
	Text=%1
	Group=GameON

[TitleLeft]
	Meter=String
	MeterStyle=PText | PTitle
	Text=FPS
	Group=GameON | FRMTimes

[TitleRight]
	Meter=String
	MeterStyle=PText | PTitle
	X=(#PHeight#*1.538)
	Text=ms
	Group=GameON | FRMTimes
	
[Info5Text]
	Meter=String
	MeterStyle=PText | PSize0
	StringAlign=Center
	X=(#PHeight#*1.538)
	Y=(#PHeight#*0.06)
	MeasureName=Measure_Frametime
	Text=%1
	Group=GameON | FRMTimes
	
[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	X=(#PHeight#*0.78)
	Y=(#PHeight#*0.27)
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	DynamicVariables=1
	Group=GameOFF
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Game#FPSViewColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.5)
	H=(#PHeight#*0.5)
	Hidden=#FPSViewColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=PText | PCenterBig | PSize8
	Y=(#PHeight#*0.2)
	Text=2D Mode
	Group=GameOFF

[Title]
	Meter=String
	MeterStyle=PText | PTitle2
	Text=#FPSViewName#
	Group=GameOFF

;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=PText | PSize10
	StringAlign=Left
	FontColor=#Panel-BarFillColor1#
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.34)
	Text=Framerate (FPS)
	Group=GameON

[GraphLabel2]
	Meter=String
	MeterStyle=PText | PSize10
	StringAlign=Right
	FontColor=#Panel-BarFillColor3#
	X=(#PHeight#*2.02)
	Y=(#PHeight#*0.34)
	Text=Frametime (ms)
	Group=GameON | FRMTimes

[MeterFPSViewGraph]
	Meter=Line
	MeasureName=Measure_FPS
	LineCount=1
	MeterStyle=GraphStyleLeft
	Group=GameON
	UpdateDivider=5

[MeterFrametimeGraph]
	Meter=Line
	MeasureName=Measure_Frametime
	LineCount=1
	MeterStyle=GraphStyleRight
	Group=GameON | FRMTimes
	UpdateDivider=5

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size