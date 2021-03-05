[variables]
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard HWiNFO Measures ----

[Measure_CPUName]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-Temp_Id#
HWiNFOSensorInstance=#CPU2-Temp_Instance#
HWiNFOEntryId		=#CPU2-Temp_EntryId#
HWiNFOType			=SensorName
RegExpSubstitute	=1
Substitute			=#CPUFilterHWiNFO#
UpdateDivider		=-1

[Measure_CPUTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-Temp_Id#
HWiNFOSensorInstance=#CPU2-Temp_Instance#
HWiNFOEntryId		=#CPU2-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUUsage]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-Usage-Total_Id#
HWiNFOSensorInstance=#CPU2-Usage-Total_Instance#
HWiNFOEntryId		=#CPU2-Usage-Total_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUVCore]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-VCore_Id#
HWiNFOSensorInstance=#CPU2-VCore_Instance#
HWiNFOEntryId		=#CPU2-VCore_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUPower]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-PackagePwr_Id#
HWiNFOSensorInstance=#CPU2-PackagePwr_Instance#
HWiNFOEntryId		=#CPU2-PackagePwr_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU0Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2A-Clock_Id#
HWiNFOSensorInstance=#CPU2A-Clock_Instance#
HWiNFOEntryId		=#CPU2A-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU1Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2B-Clock_Id#
HWiNFOSensorInstance=#CPU2B-Clock_Instance#
HWiNFOEntryId		=#CPU2B-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU2Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2C-Clock_Id#
HWiNFOSensorInstance=#CPU2C-Clock_Instance#
HWiNFOEntryId		=#CPU2C-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPU3Clock]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2D-Clock_Id#
HWiNFOSensorInstance=#CPU2D-Clock_Instance#
HWiNFOEntryId		=#CPU2D-Clock_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUFAN1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-FAN1_Id#
HWiNFOSensorInstance=#CPU2-FAN1_Instance#
HWiNFOEntryId		=#CPU2-FAN1_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_CPUFAN2_Pump]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-FAN2_Id#
HWiNFOSensorInstance=#CPU2-FAN2_Instance#
HWiNFOEntryId		=#CPU2-FAN2_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1
IfCondition=(Measure_CPUFAN2_Pump > 0)
IfTrueAction=[!SetOption Info4aText Text "%1rpm"][!SetOption Info4bText Text "%1rpm"]
IfFalseAction=[!SetOption Info4aText Text "%1"][!SetOption Info4bText Text "rpm"]

[Measure_AvgCPUClock]
Measure				=Calc
Formula				=(Measure_CPU0Clock+Measure_CPU1Clock+Measure_CPU2Clock+Measure_CPU3Clock)/4
UpdateDivider		=1

;---- Roundline Left Measures ----

[Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-LeftRL_Id#
HWiNFOSensorInstance=#CPU2-LeftRL_Instance#
HWiNFOEntryId		=#CPU2-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[Measure_LeftRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-LeftRL_Id#
HWiNFOSensorInstance=#CPU2-LeftRL_Instance#
HWiNFOEntryId		=#CPU2-LeftRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_LeftRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-LeftRL_Id#
HWiNFOSensorInstance=#CPU2-LeftRL_Instance#
HWiNFOEntryId		=#CPU2-LeftRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_LeftRL_Value-#CPU2_RLLeft_MinValue#+0.1)/(#CPU2_RLLeft_MaxValue#-#CPU2_RLLeft_MinValue#)
UpdateDivider		=1



;---- Roundline Right Measures ----

[Measure_RightRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-RightRL_Id#
HWiNFOSensorInstance=#CPU2-RightRL_Instance#
HWiNFOEntryId		=#CPU2-RightRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_RightRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-RightRL_Id#
HWiNFOSensorInstance=#CPU2-RightRL_Instance#
HWiNFOEntryId		=#CPU2-RightRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-RightRL_Id#
HWiNFOSensorInstance=#CPU2-RightRL_Instance#
HWiNFOEntryId		=#CPU2-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_RightRL_Value-#CPU2_RLRight_MinValue#+0.1)/(#CPU2_RLRight_MaxValue#-#CPU2_RLRight_MinValue#)
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
	Text=#CPU2_RLLeft_MaxValue#%1
	Hidden=#CPU2HideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=#CPU2_RLLeft_MinValue#
	Hidden=#CPU2HideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeasureName=Measure_RightRL_Units
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=#CPU2_RLRight_MaxValue#%1
	Hidden=#CPU2HideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=#CPU2_RLRight_MinValue#
	Hidden=#CPU2HideRLLabel#


;---- Graph ----

[MeterCPUGraph]
	Meter=Line
	MeasureName=Measure_LeftRL_Value
	MeasureName2=Measure_RightRL_Value
	LineCount=2
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#CPU2HideGraph#
	
[Graph Label1]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_LeftRL_Name
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.30)
	Y=(#CRadius#*0.84)
	Text=%1
	Hidden=#CPU2HideGraph#

[Graph Label2]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_RightRL_Name
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.7)
	Y=(#CRadius#*0.84)
	Text=%1
	Hidden=#CPU2HideGraph#




;---- Standard Meter

[Info1Text]
	Meter=String
	MeterStyle=CText | CSize3 | CCenter
	MeasureName=Measure_CPUUsage
	Text=%1%
	Y=(#CRadius#*0.37)
	NumOfDecimals=1
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPU2ColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*0.65+#CRadius#*#CPU2HideGraph#*0.03)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#CPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPU2ColoredIcons#
	DynamicVariables=1
[Info2aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_CPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1
[Info2bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_CPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1	
	

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPU2ColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*1.17-#CRadius#*#CPU2HideGraph#*0.25)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPU#CPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPU2ColoredIcons#
	DynamicVariables=1
[Info3aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_AvgCPUClock
	Text=%1 MHz
[Info3bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_CPUVcore
	Text=%1 V
	NumOfDecimals=2

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\CPUCooler#CPU2ColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*1.35-#CRadius#*#CPU2HideGraph#*0.15)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\CPUCooler#CPU2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#CPU2ColoredIcons#
	DynamicVariables=1
[Info4aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_CPUFAN1
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1
[Info4bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_CPUFAN2_Pump
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1




[Title]
	Meter=String
	MeasureName=Measure_CPUName
	MeterStyle=CText | CTitle
	Text=#CPU2Name#
	Hidden=0


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



