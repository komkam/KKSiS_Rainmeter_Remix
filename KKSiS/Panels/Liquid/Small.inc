[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
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
Formula				=(Measure_FAN1+Measure_FAN2+Measure_FAN3)/3
UpdateDivider		=10


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Liquid#LiquidColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Liquid#LiquidColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#LiquidColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_AvgFANSpeed
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	Text=%1 rpm [\x2205]
	DynamicVariables=1

[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_TempSensor
	MeasureName2=Measure_PumpSensor
	Text=%1[\x00B0]#TempUnit# | %2r
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	NumOfDecimals=0
	DynamicVariables=1


;---- FAN Images ----

[FAN_Rotation]
	Measure=Calc
	Formula=(FAN1_Rotation%3+1)*#Rotate1#*#Rotate2#*#Rotate3#
	DynamicVariables=1
	IfCondition=(#LiquidColoredIcons# = 0)
	IfTrueAction=[!SetOption FAN_Image ImageTint "#Panel-BGShadowColor#,100"]
	DynamicVariables=1
	
[FAN_Image]
	Meter=Image
	ImageName=#@#Images\General\FAN[FAN_Rotation].png
	ImageTint=#Panel-BarFillColor1#,150
	X=(#PHeight#*0.117)
	Y=(#PHeight#*0.087)
	H=(#PHeight#*0.12)
	AntiAlias=1
	DynamicVariables=1

	

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size