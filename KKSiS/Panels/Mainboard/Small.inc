[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
@Include6=#@#HWiNFO-Sensors.inc

;---- Measures ----

[Measure_MainboardTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-Temp_Id#
HWiNFOSensorInstance=#MB-Temp_Instance#
HWiNFOEntryId		=#MB-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_PCHTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-PCH-Temp_Id#
HWiNFOSensorInstance=#MB-PCH-Temp_Instance#
HWiNFOEntryId		=#MB-PCH-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_FAN1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN1_Id#
HWiNFOSensorInstance=#MB-FAN1_Instance#
HWiNFOEntryId		=#MB-FAN1_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_FAN2]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN2_Id#
HWiNFOSensorInstance=#MB-FAN2_Instance#
HWiNFOEntryId		=#MB-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_FAN3]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN3_Id#
HWiNFOSensorInstance=#MB-FAN3_Instance#
HWiNFOEntryId		=#MB-FAN3_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_FAN4]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN4_Id#
HWiNFOSensorInstance=#MB-FAN4_Instance#
HWiNFOEntryId		=#MB-FAN4_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10

[Measure_AvgFANSpeed]
Measure				=Calc
Formula				=(Measure_FAN1+Measure_FAN2+Measure_FAN3+Measure_FAN4)/4
UpdateDivider		=10


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Mainboard#MainboardColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Mainboard#MainboardColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#MainboardColoredIcons#
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
	MeasureName=Measure_PCHTemp
	MeasureName2=Measure_MainboardTemp
	Text=%1[\x00B0]#TempUnit# | %2[\x00B0]#TempUnit#
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	NumOfDecimals=0
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size