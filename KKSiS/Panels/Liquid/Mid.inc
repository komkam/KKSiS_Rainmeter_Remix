[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_TempSensor]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Liquid-Sensor-Temp_Id#
HWiNFOSensorInstance=#Liquid-Sensor-Temp_Instance#
HWiNFOEntryId		=#Liquid-Sensor-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_PumpSensor]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Liquid-Sensor-Pump_Id#
HWiNFOSensorInstance=#Liquid-Sensor-Pump_Instance#
HWiNFOEntryId		=#Liquid-Sensor-Pump_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_FAN1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Liquid-FAN1_Id#
HWiNFOSensorInstance=#Liquid-FAN1_Instance#
HWiNFOEntryId		=#Liquid-FAN1_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10
IfCondition			=(Measure_FAN1 > 0)
IfTrueAction		=[!SetVariable "Rotate1" "1"]
IfFalseAction		=[!SetVariable "Rotate1" "0"]

[Measure_FAN2]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Liquid-FAN2_Id#
HWiNFOSensorInstance=#Liquid-FAN2_Instance#
HWiNFOEntryId		=#Liquid-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10
IfCondition			=(Measure_FAN2 > 0)
IfTrueAction		=[!SetVariable "Rotate2" "1"]
IfFalseAction		=[!SetVariable "Rotate2" "0"]

[Measure_FAN3]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Liquid-FAN3_Id#
HWiNFOSensorInstance=#Liquid-FAN3_Instance#
HWiNFOEntryId		=#Liquid-FAN3_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10
IfCondition			=(Measure_FAN3 > 0)
IfTrueAction		=[!SetVariable "Rotate3" "1"]
IfFalseAction		=[!SetVariable "Rotate3" "0"]

[Measure_AvgFANSpeed]
Measure				=Calc
Formula				=100-100*((Measure_FAN1+Measure_FAN2+Measure_FAN3)-#Liquid_RLRight_MinValue#)/(#Liquid_RLRight_MaxValue#-#Liquid_RLRight_MinValue#)
UpdateDivider		=10
MaxValue			=100
MinValue			=0

;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Tank#LiquidColoredIcons#.png
	X=(#PHeight#*0.13+#LiquidHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.06)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Tank#LiquidColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#LiquidColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_TempSensor
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Pump#LiquidColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Pump#LiquidColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#LiquidColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_PumpSensor
	Text=%1rpm
	NumOfDecimals=0
	DynamicVariables=1

[Radiator_Image]
	Meter=Image
	ImageName=#@#Images\General\Radiator.png
	ImageRotate=90
	X=(#PHeight#*0.115+#LiquidHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.2)r
	H=(#PHeight#*0.5)
	DynamicVariables=1

;---- FAN Images ----

[FAN1_Rotation]
	Measure=Calc
	Formula=(FAN1_Rotation%3+1)*#Rotate1#
	DynamicVariables=1
[FAN2_Rotation]
	Measure=Calc
	Formula=(FAN2_Rotation%3+1)*#Rotate2#
	DynamicVariables=1
[FAN3_Rotation]
	Measure=Calc
	Formula=(FAN3_Rotation%3+1)*#Rotate3#
	DynamicVariables=1
	IfCondition=(#LiquidColoredIcons# = 0)
	IfTrueAction=[!SetOption FAN1_Image ImageTint "#Panel-BGShadowColor#,100"][!SetOption FAN2_Image ImageTint "#Panel-BGShadowColor#,100"][!SetOption FAN3_Image ImageTint "#Panel-BGShadowColor#,100"]

[FAN_Style]
	ImageTint=#Panel-BarFillColor1#,150
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.17)r
	H=(#PHeight#*0.14)
	AntiAlias=1
	DynamicVariables=1

[FAN1_Image]
	Meter=Image
	ImageName=#@#Images\General\FAN[FAN1_Rotation].png
	MeterStyle=FAN_Style
	X=(#PHeight#*0.1215+#LiquidHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.036)r
	
[FAN1RPM]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Left
	MeasureName=Measure_FAN1
	Text=%1 rpm
	DynamicVariables=1
	
[FAN2_Image]
	Meter=Image
	ImageName=#@#Images\General\FAN[FAN2_Rotation].png
	MeterStyle=FAN_Style

[FAN2RPM]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Left
	MeasureName=Measure_FAN2
	Text=%1 rpm
	DynamicVariables=1
	
[FAN3_Image]
	Meter=Image
	ImageName=#@#Images\General\FAN[FAN3_Rotation].png
	MeterStyle=FAN_Style

[FAN3RPM]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Left
	MeasureName=Measure_FAN3
	Text=%1 rpm
	DynamicVariables=1
	
	
[Title]
	Meter=String
	MeasureName=Measure_LiquidName
	MeterStyle=PText | PTitle
	Text=#LiquidName#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#LiquidHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_AvgFANSpeed
UpdateDivider=1
Hidden=#LiquidHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#LiquidHideGraph#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size