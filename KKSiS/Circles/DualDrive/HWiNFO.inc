[variables]
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_DriveSpaceMaxA]
Measure				=FreeDiskSpace
Drive				=#DualDriveDiskALetter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpaceMaxB]
Measure				=FreeDiskSpace
Drive				=#DualDriveDiskBLetter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpaceA1]
Measure				=FreeDiskSpace
Drive				=#DualDriveDiskALetter#:

[Measure_DriveSpaceA0]
Measure				=Calc
Formula				=Measure_DriveSpaceMaxA-Measure_DriveSpaceA1

[Measure_DriveSpaceB1]
Measure				=FreeDiskSpace
Drive				=#DualDriveDiskBLetter#:

[Measure_DriveSpaceB0]
Measure				=Calc
Formula				=Measure_DriveSpaceMaxB-Measure_DriveSpaceB1

[Measure_DrivePercentageA0]
Measure				=Calc
Formula				=100-100*(Measure_DriveSpaceA0/Measure_DriveSpaceMaxA)

[Measure_DrivePercentageA1]
Measure				=Calc
Formula				=100*(Measure_DriveSpaceA0/Measure_DriveSpaceMaxA)

[Measure_DrivePercentageB0]
Measure				=Calc
Formula				=100-100*(Measure_DriveSpaceB0/Measure_DriveSpaceMaxB)

[Measure_DrivePercentageB1]
Measure				=Calc
Formula				=100*(Measure_DriveSpaceB0/Measure_DriveSpaceMaxB)

[Measure_DriveReadWriteRawA]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=LogicalDisk
Counter				=Bytes/s
Instance			=#DualDriveDiskALetter#:
Index				=0
Whitelist			=#DualDriveDiskALetter#:

[Measure_DriveReadWriteA]
Measure				=Calc
Formula				=[Measure_DriveReadWriteRawA:]
DynamicVariables	=1

[Measure_DriveReadWriteRawB]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=LogicalDisk
Counter				=Bytes/s
Instance			=#DualDriveDiskBLetter#:
Index				=0
Whitelist			=#DualDriveDiskBLetter#:

[Measure_DriveReadWriteB]
Measure				=Calc
Formula				=[Measure_DriveReadWriteRawB:]
DynamicVariables	=1

[Measure_DriveALabel]
Measure				=FreeDiskSpace
Drive				=#DualDriveDiskALetter#:
Label				=1
UpdateDivider		=-1

[Measure_DriveBLabel]
Measure				=FreeDiskSpace
Drive				=#DualDriveDiskBLetter#:
Label				=1
UpdateDivider		=-1


;---- Standard HWiNFO Measures ----

[Measure_Drive1]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive1-Temp_Id#
HWiNFOSensorInstance=#Drive1-Temp_Instance#
HWiNFOEntryId		=#Drive1-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_Drive2]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive2-Temp_Id#
HWiNFOSensorInstance=#Drive2-Temp_Instance#
HWiNFOEntryId		=#Drive2-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_Drive3]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive3-Temp_Id#
HWiNFOSensorInstance=#Drive3-Temp_Instance#
HWiNFOEntryId		=#Drive3-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_Drive4]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive4-Temp_Id#
HWiNFOSensorInstance=#Drive4-Temp_Instance#
HWiNFOEntryId		=#Drive4-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_Drive5]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive5-Temp_Id#
HWiNFOSensorInstance=#Drive5-Temp_Instance#
HWiNFOEntryId		=#Drive5-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=Measure_DrivePercentageA#DualDriveShowFreeSpace#
ValueRemainder=100

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=Measure_DrivePercentageB#DualDriveShowFreeSpace#
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


;---- Roundline Left Meter ----

[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_DriveSpaceMaxA
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=%1
	AutoScale=1
	NumOfDecimals=0
	Hidden=#DualDriveHideRLLabel#

[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#DualDriveHideRLLabel#


---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_DriveSpaceMaxB
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=%1
	AutoScale=1
	NumOfDecimals=0
	Hidden=#DualDriveHideRLLabel#

[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#DualDriveHideRLLabel#


;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_DriveALabel
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.52)
	Y=(#CRadius#*1.51)
	Text=%1
	Hidden=#DualDriveHideGraph#

[GraphLabel2]
	Meter=String
	MeterStyle=CText | CSize9
	MeasureName=Measure_DriveBLabel
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.48)
	Y=(#CRadius#*1.51)
	Text=%1
	Hidden=#DualDriveHideGraph#

[Graph]
	Meter=Line
	MeasureName=Measure_DriveReadWriteA
	MeasureName2=Measure_DriveReadWriteB
	LineCount=2
	Y=(#CRadius#*1.52)
	H=(#CRadius#*0.25)
	MeterStyle=HWiNFOGraphStyle
	Hidden=#DualDriveHideGraph#


;---- Standard Meter ----

[Info]
	Meter=String
	MeterStyle=CText | CSize6 | CCenter 
	Y=(#CRadius#*0.30)
	Text=#VarUsed#

[InfoDiskA]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.40)
	Y=(#CRadius#*0.635)
	Text=#DualDriveDiskALetter#
	Hidden=#DualDriveHideGraph#
	
[InfoDiskB]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*1.50)
	Y=(#CRadius#*1.14)
	Text=#DualDriveDiskBLetter#
	Hidden=#DualDriveHideGraph#
	
[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDriveSSD##DualDriveColoredIcons#.png
	X=(#CRadius#*0.56)
	Y=(#CRadius#*0.48)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDriveSSD##DualDriveColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#DualDriveColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_DriveSpaceA0
	MeasureName2=Measure_DriveSpaceA1
	MeasureName3=Measure_DrivePercentageA1
	MeasureName4=Measure_DrivePercentageA0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[SelectionA]
	Measure=String
	String=#DualDriveDiskALetter#
	IfMatch=#Drive1Letter#
	IfMatchAction=[!SetOption Info2Text MeasureName Measure_Drive1]
	IfMatch2=#Drive2Letter#
	IfMatchAction2=[!SetOption Info2Text MeasureName Measure_Drive2]
	IfMatch3=#Drive3Letter#
	IfMatchAction3=[!SetOption Info2Text MeasureName Measure_Drive3]
	IfMatch4=#Drive4Letter#
	IfMatchAction4=[!SetOption Info2Text MeasureName Measure_Drive4]
	IfMatch5=#Drive5Letter#
	IfMatchAction5=[!SetOption Info2Text MeasureName Measure_Drive5]
	DynamicVariables=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDriveColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*0.19)r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDriveColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#DualDriveColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=0

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDriveColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*0.19)r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\IconsReadWrite#DualDriveColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#DualDriveColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=CText | CInfo
	MeasureName=Measure_DriveReadWriteA
	Text=%1B/s
	AutoScale=1
	NumOfDecimals=1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDriveSSD##DualDriveColoredIcons#.png
	X=(#CRadius#*1.28)
	Y=(#CRadius#*0.19)r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDriveSSD##DualDriveColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#DualDriveColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Right
	X=(-#CRadius#*0.04)r
	MeasureName=Measure_DriveSpaceB0
	MeasureName2=Measure_DriveSpaceB1
	MeasureName3=Measure_DrivePercentageB1
	MeasureName4=Measure_DrivePercentageB0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[SelectionB]
	Measure=String
	String=#DualDriveDiskBLetter#
	IfMatch=#Drive1Letter#
	IfMatchAction=[!SetOption Info5Text MeasureName Measure_Drive1]
	IfMatch2=#Drive2Letter#
	IfMatchAction2=[!SetOption Info5Text MeasureName Measure_Drive2]
	IfMatch3=#Drive3Letter#
	IfMatchAction3=[!SetOption Info5Text MeasureName Measure_Drive3]
	IfMatch4=#Drive4Letter#
	IfMatchAction4=[!SetOption Info5Text MeasureName Measure_Drive4]
	IfMatch5=#Drive5Letter#
	IfMatchAction5=[!SetOption Info5Text MeasureName Measure_Drive5]
	DynamicVariables=1
	
[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDriveColoredIcons#.png
	X=(#CRadius#*0.04)r
	Y=(#CRadius#*0.19)r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDriveColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#DualDriveColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Right
	X=(-#CRadius#*0.04)r
	MeasureName=
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=0

[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDriveColoredIcons#.png
	X=(#CRadius#*0.04)r
	Y=(#CRadius#*0.19)r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\IconsReadWrite#DualDriveColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#DualDriveColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=CText | CInfo
	StringAlign=Right
	X=(-#CRadius#*0.04)r
	MeasureName=Measure_DriveReadWriteB
	Text=%1B/s
	AutoScale=1
	NumOfDecimals=1
	DynamicVariables=1

[TitleA]
	Meter=String
	MeterStyle=CText | CTitle
	StringAlign=Left
	Text=#DualDriveDiskALetter#
	X=(#CRadius#*0.45)

[TitleB]
	Meter=String
	MeterStyle=CText | CTitle
	StringAlign=Right
	Text=#DualDriveDiskBLetter#
	X=(#CRadius#*1.55)

;---- Options ----

[Selection]
	Measure=Calc
	Formula=#DualDriveShowPercentage#+#DualDriveShowFreeSpace#+#DualDriveHideGraph#
	UpdateRate=-1
	IfCondition=(#DualDriveShowPercentage# = 0) && (#DualDriveShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%1B"][!SetOption Info4Text Text "%1B"]
	IfCondition2=(#DualDriveShowPercentage# = 0) && (#DualDriveShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%2B"][!SetOption Info4Text Text "%2B"]
	IfCondition3=(#DualDriveShowPercentage# = 1) && (#DualDriveShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text #VarUsed#][!SetOption Info1Text Text "%3%"][!SetOption Info4Text Text "%3%"]
	IfCondition4=(#DualDriveShowPercentage# = 1) && (#DualDriveShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text #VarFree#][!SetOption Info1Text Text "%4%"][!SetOption Info4Text Text "%4%"]
	IfCondition5=(#DualDriveHideGraph# = 0) 
	IfTrueAction5=[!HideMeter TitleA][!HideMeter TitleB]
	DynamicVariables=1
	UpdateDivider=-1

;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size



