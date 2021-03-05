[variables]
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
IfTrueAction=[!SetOption Info4aText Text "%1rpm"][!SetOption Info4bText Text "%1rpm"]
IfFalseAction=[!SetOption Info4aText Text "%1"][!SetOption Info4bText Text "rpm"]


;---- Roundline Left Measures ----

[Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-LeftRL_Id#
HWiNFOSensorInstance=#GPU-LeftRL_Instance#
HWiNFOEntryId		=#GPU-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[Measure_LeftRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-LeftRL_Id#
HWiNFOSensorInstance=#GPU-LeftRL_Instance#
HWiNFOEntryId		=#GPU-LeftRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_LeftRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-LeftRL_Id#
HWiNFOSensorInstance=#GPU-LeftRL_Instance#
HWiNFOEntryId		=#GPU-LeftRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_LeftRL_Value-#GPU_RLLeft_MinValue#+0.1)/(#GPU_RLLeft_MaxValue#-#GPU_RLLeft_MinValue#)
UpdateDivider		=1



;---- Roundline Right Measures ----

[Measure_RightRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-RightRL_Id#
HWiNFOSensorInstance=#GPU-RightRL_Instance#
HWiNFOEntryId		=#GPU-RightRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_RightRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-RightRL_Id#
HWiNFOSensorInstance=#GPU-RightRL_Instance#
HWiNFOEntryId		=#GPU-RightRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-RightRL_Id#
HWiNFOSensorInstance=#GPU-RightRL_Instance#
HWiNFOEntryId		=#GPU-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_RightRL_Value-#GPU_RLRight_MinValue#+0.1)/(#GPU_RLRight_MaxValue#-#GPU_RLRight_MinValue#)
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
	MouseOverAction=[!ShowMeterGroup ProcList]
	MouseLeaveAction=[!HideMeterGroup ProcList]

;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeasureName=Measure_LeftRL_Units
	MeterStyle=CText | CSize6
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=#GPU_RLLeft_MaxValue#%1
	Hidden=#GPUHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=#GPU_RLLeft_MinValue#
	Hidden=#GPUHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeasureName=Measure_RightRL_Units
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=#GPU_RLRight_MaxValue#%1
	Hidden=#GPUHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=#GPU_RLRight_MinValue#
	Hidden=#GPUHideRLLabel#


;---- Graph ----

[MeterGPUGraph]
	Meter=Line
	MeasureName=Measure_LeftRL_Value
	MeasureName2=Measure_RightRL_Value
	LineCount=2
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#GPUHideGraph#
	
[Graph Label1]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_LeftRL_Name
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.30)
	Y=(#CRadius#*0.84)
	Text=%1
	Hidden=#GPUHideGraph#

[Graph Label2]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_RightRL_Name
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.7)
	Y=(#CRadius#*0.84)
	Text=%1
	Hidden=#GPUHideGraph#


;---- Standard Meter

[Info1Text]
	Meter=String
	MeterStyle=CText | CSize3 | CCenter
	MeasureName=Measure_GPUUsage
	Text=%1%
	Y=(#CRadius#*0.37)
	NumOfDecimals=1
	DynamicVariables=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Power#GPUColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*0.65+#CRadius#*#GPUHideGraph#*0.03)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Power#GPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info2aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_GPUTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1
	DynamicVariables=1
[Info2bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_GPUPower
	Text=%1 W
	NumOfDecimals=1
	DynamicVariables=1	
	

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*1.17-#CRadius#*#GPUHideGraph#*0.25)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\GPU#GPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info3aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_GPUClock
	Text=%1 MHz
	DynamicVariables=1
[Info3bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_VRAM
	Text=%1 MB
	NumOfDecimals=0
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\FAN#GPUColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*1.35-#CRadius#*#GPUHideGraph#*0.15)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\FAN#GPUColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#GPUColoredIcons#
	DynamicVariables=1
[Info4aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_GPUFAN1
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1
[Info4bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_GPUFAN2
	Text=%1 rpm
	NumOfDecimals=0
	DynamicVariables=1


[Title]
	Meter=String
	MeasureName=Measure_GPUName
	MeterStyle=CText | CTitle
	Text=#GPUName#
	Hidden=0


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



