[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_MainboardName]
Measure				=Registry
RegHKey				=HKEY_LOCAL_MACHINE
RegKey				=HARDWARE\DESCRIPTION\System\BIOS
RegValue			=BaseBoardProduct
RegExpSubstitute	=1
Substitute			=#MainboardFilterWindows#
UpdateDivider		=-1


;---- Standard HWiNFO Measures ----

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

[Measure_PCHTemp2]
Measure				=Calc
Formula				=100-Measure_PCHTemp
MaxValue			=100
MinValue			=0
UpdateDivider		=10

[Measure_TempSensor]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-Sensor-Temp_Id#
HWiNFOSensorInstance=#MB-Sensor-Temp_Instance#
HWiNFOEntryId		=#MB-Sensor-Temp_EntryId#
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
IfCondition			=(Measure_FAN1 > 0)
IfTrueAction		=[!SetVariable "Rotate1" "1"]
IfFalseAction		=[!SetVariable "Rotate1" "0"]

[Measure_FAN2]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN2_Id#
HWiNFOSensorInstance=#MB-FAN2_Instance#
HWiNFOEntryId		=#MB-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10
IfCondition			=(Measure_FAN2 > 0)
IfTrueAction		=[!SetVariable "Rotate2" "1"]
IfFalseAction		=[!SetVariable "Rotate2" "0"]

[Measure_FAN3]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN3_Id#
HWiNFOSensorInstance=#MB-FAN3_Instance#
HWiNFOEntryId		=#MB-FAN3_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10
IfCondition			=(Measure_FAN3 > 0)
IfTrueAction		=[!SetVariable "Rotate3" "1"]
IfFalseAction		=[!SetVariable "Rotate3" "0"]

[Measure_FAN4]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#MB-FAN4_Id#
HWiNFOSensorInstance=#MB-FAN4_Instance#
HWiNFOEntryId		=#MB-FAN4_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=10
IfCondition			=(Measure_FAN4 > 0)
IfTrueAction		=[!SetVariable "Rotate4" "1"]
IfFalseAction		=[!SetVariable "Rotate4" "0"]


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Mainboard#MainboardColoredIcons#.png
	X=(#PHeight#*0.13+#MainboardHideGraph#*#PHeight#*0.03)
	Y=(#PHeight#*0.06)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Mainboard#MainboardColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#MainboardColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_MainboardTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#MainboardColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#MainboardColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#MainboardColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_PCHTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
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
[FAN4_Rotation]
	Measure=Calc
	Formula=(FAN4_Rotation%3+1)*#Rotate4#
	DynamicVariables=1
	IfCondition=(#MainboardColoredIcons# = 0)
	IfTrueAction=[!SetOption FAN1_Image ImageTint "#Panel-BGShadowColor#,100"][!SetOption FAN2_Image ImageTint "#Panel-BGShadowColor#,100"][!SetOption FAN3_Image ImageTint "#Panel-BGShadowColor#,100"][!SetOption FAN4_Image ImageTint "#Panel-BGShadowColor#,100"]
	
[FAN_Style]
	;ImageTint=#Panel-BGShadowColor#,100
	ImageTint=#Panel-BarFillColor1#,150
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	H=(#PHeight#*0.12)
	AntiAlias=1
	DynamicVariables=1

[FAN1_Image]
	Meter=Image
	ImageName=#@#Images\General\FAN[FAN1_Rotation].png
	MeterStyle=FAN_Style
	X=(#PHeight#*0.13+#MainboardHideGraph#*#PHeight#*0.03)
	
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
	
[FAN4_Image]
	Meter=Image
	ImageName=#@#Images\General\FAN[FAN4_Rotation].png
	MeterStyle=FAN_Style

[FAN4RPM]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Left
	MeasureName=Measure_FAN4
	Text=%1 rpm
	DynamicVariables=1

	
[Title]
	Meter=String
	MeasureName=Measure_MainboardName
	MeterStyle=PText | PTitle
	Text=#MainboardName#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#MainboardHideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_PCHTemp2
UpdateDivider=1
Hidden=#MainboardHideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#MainboardHideGraph#

[Bar1Marker]
Meter=Shape
Shape=Rectangle (#PHeight#*0.05),(#PHeight#*0.33),(#PHeight#*0.9),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-StrokeColor#
UpdateDivider=1
DynamicVariables=1
Hidden=#MainboardHideGraph#


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size