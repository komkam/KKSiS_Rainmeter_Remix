[variables]
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_DriveSpaceMax]
Measure				=FreeDiskSpace
Drive				=#Drive7Letter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpace1]
Measure				=FreeDiskSpace
Drive				=#Drive7Letter#:

[Measure_DriveSpace0]
Measure				=Calc
Formula				=Measure_DriveSpaceMax-Measure_DriveSpace1

[Measure_DriveLabel]
Measure				=FreeDiskSpace
Drive				=#Drive7Letter#:
Label				=1
UpdateDivider		=-1

[Measure_DrivePercentage0]
Measure				=Calc
Formula				=100-100*(Measure_DriveSpace0/Measure_DriveSpaceMax)

[Measure_DrivePercentage1]
Measure				=Calc
Formula				=100*(Measure_DriveSpace0/Measure_DriveSpaceMax)


;---- Standard HWiNFO Measures ----

[Measure_DriveTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-Temp_Id#
HWiNFOSensorInstance=#Drive7-Temp_Instance#
HWiNFOEntryId		=#Drive7-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveActivity]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-TotalActivity_Id#
HWiNFOSensorInstance=#Drive7-TotalActivity_Instance#
HWiNFOEntryId		=#Drive7-TotalActivity_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveRead]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-ReadRate_Id#
HWiNFOSensorInstance=#Drive7-ReadRate_Instance#
HWiNFOEntryId		=#Drive7-ReadRate_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveWrite]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-WriteRate_Id#
HWiNFOSensorInstance=#Drive7-WriteRate_Instance#
HWiNFOEntryId		=#Drive7-WriteRate_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1


;---- Roundline Left Measures ----

[Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-LeftRL_Id#
HWiNFOSensorInstance=#Drive7-LeftRL_Instance#
HWiNFOEntryId		=#Drive7-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[Measure_LeftRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-LeftRL_Id#
HWiNFOSensorInstance=#Drive7-LeftRL_Instance#
HWiNFOEntryId		=#Drive7-LeftRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_LeftRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-LeftRL_Id#
HWiNFOSensorInstance=#Drive7-LeftRL_Instance#
HWiNFOEntryId		=#Drive7-LeftRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[SmoothLeftRoundline]
Measure				=Calc
Formula				=100-100*(Measure_LeftRL_Value-#Drive7_RLLeft_MinValue#+0.1)/(#Drive7_RLLeft_MaxValue#-#Drive7_RLLeft_MinValue#)
UpdateDivider		=1


;---- Roundline Right Measures ----

[Measure_RightRL_Units]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-RightRL_Id#
HWiNFOSensorInstance=#Drive7-RightRL_Instance#
HWiNFOEntryId		=#Drive7-RightRL_EntryId#
HWiNFOType			=Units
UpdateDivider		=-1

[Measure_RightRL_Value]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-RightRL_Id#
HWiNFOSensorInstance=#Drive7-RightRL_Instance#
HWiNFOEntryId		=#Drive7-RightRL_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-RightRL_Id#
HWiNFOSensorInstance=#Drive7-RightRL_Instance#
HWiNFOEntryId		=#Drive7-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=-1

[SmoothRightRoundline]
Measure				=Calc
Formula				=100-100*(Measure_RightRL_Value-#Drive7_RLRight_MinValue#+0.1)/(#Drive7_RLRight_MaxValue#-#Drive7_RLRight_MinValue#)
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
LeftMouseUpAction=["#Drive7Letter#:"]


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_LeftRL_Units
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=#Drive7_RLLeft_MaxValue#%1
	AutoScale=1
	NumOfDecimals=0
	Hidden=#Drive7HideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.456)
	Text=#Drive7_RLLeft_MinValue#
	Hidden=#Drive7HideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_RightRL_Units
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=#Drive7_RLRight_MaxValue#%1
	AutoScale=1
	NumOfDecimals=0
	Hidden=#Drive7HideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.456)
	Text=#Drive7_RLRight_MinValue#
	Hidden=#Drive7HideRLLabel#


;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_LeftRL_Name
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.31)
	Y=(#CRadius#*0.79)
	Text=%1
	Hidden=#Drive7HideGraph#

[GraphLabel2]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_RightRL_Name
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.69)
	Y=(#CRadius#*0.79)
	Text=%1
	Hidden=#Drive7HideGraph#

[Graph]
	Meter=Line
	MeasureName=Measure_LeftRL_Value
	MeasureName2=Measure_RightRL_Value
	LineCount=2
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#Drive7HideGraph#


;---- Standard Meter ----

[Info]
	Meter=String
	MeterStyle=CText | CInfo | CCenter 
	Y=(#CRadius#*0.32)
	Text=#VarUsed#
	
[Info1Text]
	Meter=String
	MeterStyle=CText | CCenter
	FontSize=(#CRadius#*(0.22+0.04*#Drive7HideGraph#))
	Y=(#CRadius#*(0.48+#Drive7HideGraph#*0.08))
	MeasureName=Measure_DriveSpace0
	MeasureName2=Measure_DriveSpace1
	MeasureName3=Measure_DrivePercentage1
	MeasureName4=Measure_DrivePercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#Drive7ColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*(1.17-#Drive7HideGraph#*0.15))
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#Drive7ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#Drive7ColoredIcons#
	DynamicVariables=1
[Info2aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_DriveRead
	Text=%1 MB/s
	NumOfDecimals=0
[Info2bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_DriveWrite
	Text=%1 MB/s
	NumOfDecimals=0

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive7SSD##Drive7ColoredIcons#.png
	X=(#CRadius#*0.92)
	Y=(#CRadius#*1.35-#CRadius#*#Drive7HideGraph#*0.10)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive7SSD##Drive7ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#Drive7ColoredIcons#
	DynamicVariables=1
[Info3aText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Right
	X=(-#CRadius#*0.01)r
	Y=0r
	MeasureName=Measure_DriveTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=0
	DynamicVariables=1
[Info3bText]
	Meter=String
	MeterStyle=CText | CSize5
	StringAlign=Left
	X=(#CRadius#*0.18)r
	Y=0r
	MeasureName=Measure_DriveActivity
	Text=%1 %
	NumOfDecimals=1
	DynamicVariables=1

[Title]
	Meter=String
	MeasureName=Measure_DriveLabel
	MeterStyle=CText | CTitle
	Text=#Drive7Letter#: #Drive7Name#
	Hidden=0


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive7ShowPercentage#+#Drive7ShowFreeSpace#+#Drive7ShowUsageinLeftRL#+#Drive7ShowUsageinRightRL#
	UpdateRate=-1
	IfCondition=(#Drive7ShowPercentage# = 0) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%1B"]
	IfCondition2=(#Drive7ShowPercentage# = 0) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%2B"]
	IfCondition3=(#Drive7ShowPercentage# = 1) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%3%"]
	IfCondition4=(#Drive7ShowPercentage# = 1) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%4%"]
	IfCondition5=(#Drive7ShowUsageinLeftRL# = 1) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction5=[!SetOption "Measure-Roundline-Left" "MeasureName" "Measure_DrivePercentage0"][!SetOption "SensorLeftMax" "MeasureName" "Measure_DriveSpaceMax"][!SetOption "SensorLeftMax" "Text" "%1B"]
	IfCondition6=(#Drive7ShowUsageinLeftRL# = 1) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction6=[!SetOption "Measure-Roundline-Left" "MeasureName" "Measure_DrivePercentage1"][!SetOption "SensorLeftMax" "MeasureName" "Measure_DriveSpaceMax"][!SetOption "SensorLeftMax" "Text" "%1B"]
	IfCondition7=(#Drive7ShowUsageinRightRL# = 1) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction7=[!SetOption "Measure-Roundline-Right" "MeasureName" "Measure_DrivePercentage0"][!SetOption "SensorRightMax" "MeasureName" "Measure_DriveSpaceMax"][!SetOption "SensorRightMax" "Text" "%1B"]
	IfCondition8=(#Drive7ShowUsageinRightRL# = 1) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction8=[!SetOption "Measure-Roundline-Right" "MeasureName" "Measure_DrivePercentage1"][!SetOption "SensorRightMax" "MeasureName" "Measure_DriveSpaceMax"][!SetOption "SensorRightMax" "Text" "%1B"]
	DynamicVariables=1

;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



