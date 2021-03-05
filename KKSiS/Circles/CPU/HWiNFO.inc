[variables]
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_CPUName]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Temp_Id#
HWiNFOSensorInstance=#CPU-Temp_Instance#
HWiNFOEntryId		=#CPU-Temp_EntryId#
HWiNFOType			=SensorName
RegExpSubstitute	=1
Substitute			=#CPUFilterHWiNFO#
UpdateDivider		=-1

[Measure_CPUTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Temp_Id#
HWiNFOSensorInstance=#CPU-Temp_Instance#
HWiNFOEntryId		=#CPU-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUUsage]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-Usage-Total_Id#
HWiNFOSensorInstance=#CPU-Usage-Total_Instance#
HWiNFOEntryId		=#CPU-Usage-Total_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUVCore]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-VCore_Id#
HWiNFOSensorInstance=#CPU-VCore_Instance#
HWiNFOEntryId		=#CPU-VCore_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUPower]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-PackagePwr_Id#
HWiNFOSensorInstance=#CPU-PackagePwr_Instance#
HWiNFOEntryId		=#CPU-PackagePwr_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU0Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUA-Clock_Id#
HWiNFOSensorInstance=#CPUA-Clock_Instance#
HWiNFOEntryId		=#CPUA-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU1Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUB-Clock_Id#
HWiNFOSensorInstance=#CPUB-Clock_Instance#
HWiNFOEntryId		=#CPUB-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU2Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUC-Clock_Id#
HWiNFOSensorInstance=#CPUC-Clock_Instance#
HWiNFOEntryId		=#CPUC-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU3Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPUD-Clock_Id#
HWiNFOSensorInstance=#CPUD-Clock_Instance#
HWiNFOEntryId		=#CPUD-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUFAN1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-FAN1_Id#
HWiNFOSensorInstance=#CPU-FAN1_Instance#
HWiNFOEntryId		=#CPU-FAN1_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUFAN2_Pump]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-FAN2_Id#
HWiNFOSensorInstance=#CPU-FAN2_Instance#
HWiNFOEntryId		=#CPU-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1
IfCondition=(Measure_CPUFAN2_Pump > 0)
IfTrueAction=[!SetOption Info4Text Text "%1 | %2"]
IfFalseAction=[!SetOption Info4Text Text "%1 rpm"]

[Measure_AvgCPUClock]
Measure				=Calc
Formula				=(Measure_CPU0Clock+Measure_CPU1Clock+Measure_CPU2Clock+Measure_CPU3Clock)/4
UpdateDivider		=1

;---- Roundline Left Measures ----

[Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-LeftRL_Id#
HWiNFOSensorInstance=#CPU-LeftRL_Instance#
HWiNFOEntryId		=#CPU-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[Measure_LeftRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-LeftRL_Id#
HWiNFOSensorInstance=#CPU-LeftRL_Instance#
HWiNFOEntryId		=#CPU-LeftRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_LeftRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-LeftRL_Id#
HWiNFOSensorInstance=#CPU-LeftRL_Instance#
HWiNFOEntryId		=#CPU-LeftRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_LeftRL_Value-#CPU_RLLeft_MinValue#+0.1)/(#CPU_RLLeft_MaxValue#-#CPU_RLLeft_MinValue#)
UpdateDivider		=1



;---- Roundline Right Measures ----

[Measure_RightRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-RightRL_Id#
HWiNFOSensorInstance=#CPU-RightRL_Instance#
HWiNFOEntryId		=#CPU-RightRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_RightRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-RightRL_Id#
HWiNFOSensorInstance=#CPU-RightRL_Instance#
HWiNFOEntryId		=#CPU-RightRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-RightRL_Id#
HWiNFOSensorInstance=#CPU-RightRL_Instance#
HWiNFOEntryId		=#CPU-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_RightRL_Value-#CPU_RLRight_MinValue#+0.1)/(#CPU_RLRight_MaxValue#-#CPU_RLRight_MinValue#)
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
	LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]
	MouseOverAction=[!ShowMeterGroup ProcList]
	MouseLeaveAction=[!HideMeterGroup ProcList]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=taskmgr


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeasureName=Measure_LeftRL_Units
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=#CPU_RLLeft_MaxValue#%1
	Hidden=#CPUHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=#CPU_RLLeft_MinValue#
	Hidden=#CPUHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeasureName=Measure_RightRL_Units
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=#CPU_RLRight_MaxValue#%1
	Hidden=#CPUHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=#CPU_RLRight_MinValue#
	Hidden=#CPUHideRLLabel#


;---- Graph ----

[Graph Label1]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_LeftRL_Name
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.45)
	Y=(#CRadius#*1.4)
	Text=%1
	Hidden=#CPUHideGraph#

[Graph Label2]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_RightRL_Name
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.55)
	Y=(#CRadius#*1.4)
	Text=%1
	Hidden=#CPUHideGraph#

[MeterCPUGraph]
	Meter=Line
	MeasureName=Measure_LeftRL_Value
	MeasureName2=Measure_RightRL_Value
	LineCount=2
	MeterStyle=HWiNFOGraphStyle
	Hidden=#CPUHideGraph#


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*0.4)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_AvgCPUClock
	Text=%1 MHz
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\VCC#CPUColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#CPUHideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\VCC#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_CPUVcore
	Text=%1 V
	NumOfDecimals=3
	DynamicVariables=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPUColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#CPUHideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_CPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPUCooler#CPUColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#CPUHideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPUCooler#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_CPUFAN1
	MeasureName2=Measure_CPUFAN2_Pump
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#CPUColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#CPUHideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_CPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#CPUColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+#CPUHideGraph#*0.02))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#CPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPUColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_CPUUsage
	Text=%1%
	NumOfDecimals=1
	DynamicVariables=1


[Title]
	Meter=String
	MeasureName=Measure_CPUName
	MeterStyle=CText | CTitle
	Text=#CPUName#
	Hidden=0


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



