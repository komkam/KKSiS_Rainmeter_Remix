[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_DriveSpaceMaxA]
Measure				=FreeDiskSpace
Drive				=#DualDrive2DiskALetter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpaceMaxB]
Measure				=FreeDiskSpace
Drive				=#DualDrive2DiskBLetter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpaceA1]
Measure				=FreeDiskSpace
Drive				=#DualDrive2DiskALetter#:

[Measure_DriveSpaceA0]
Measure				=Calc
Formula				=Measure_DriveSpaceMaxA-Measure_DriveSpaceA1

[Measure_DriveSpaceB1]
Measure				=FreeDiskSpace
Drive				=#DualDrive2DiskBLetter#:

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
Instance			=#DualDrive2DiskALetter#:
Index				=0
Whitelist			=#DualDrive2DiskALetter#:

[Measure_DriveReadWriteA]
Measure				=Calc
Formula				=[Measure_DriveReadWriteRawA:]
DynamicVariables	=1

[Measure_DriveReadWriteRawB]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=LogicalDisk
Counter				=Bytes/s
Instance			=#DualDrive2DiskBLetter#:
Index				=0
Whitelist			=#DualDrive2DiskBLetter#:

[Measure_DriveReadWriteB]
Measure				=Calc
Formula				=[Measure_DriveReadWriteRawB:]
DynamicVariables	=1

[Measure_DriveLabelA]
Measure				=FreeDiskSpace
Drive				=#DualDrive2DiskALetter#:
Label				=1
UpdateDivider		=-1

[Measure_DriveLabelB]
Measure				=FreeDiskSpace
Drive				=#DualDrive2DiskBLetter#:
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


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDrive2SSD##DualDrive2ColoredIcons#.png
	X=(#PHeight#*0.943)
	Y=(#PHeight#*0.11)
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDrive2SSD##DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info1TextA]
	Meter=String
	MeterStyle=PText | PSize0
	StringAlign=Right
	X=(#PHeight#*0.903)
	Y=(#PHeight#*0.06)
	MeasureName=Measure_DriveSpaceA0
	MeasureName2=Measure_DriveSpaceA1
	MeasureName3=Measure_DrivePercentageA1
	MeasureName4=Measure_DrivePercentageA0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
[Info1TextB]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Right
	MeasureName=Measure_DriveSpaceMaxA
	X=0r
	Y=(#PHeight#*0.26)
	Text=%1B
	AutoScale=1
	NumOfDecimals=0
	
[Info2TextA]
	Meter=String
	MeterStyle=PText | PSize0
	StringAlign=Left
	X=(#PHeight#*1.173)
	Y=(#PHeight#*0.06)
	MeasureName=Measure_DriveSpaceB0
	MeasureName2=Measure_DriveSpaceB1
	MeasureName3=Measure_DrivePercentageB1
	MeasureName4=Measure_DrivePercentageB0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
[Info2TextB]
	Meter=String
	MeterStyle=PText | PSize5
	StringAlign=Left
	MeasureName=Measure_DriveSpaceMaxB
	X=0r
	Y=(#PHeight#*0.26)
	Text=%1B
	AutoScale=1
	NumOfDecimals=0
	
[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDrive2ColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.65)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveReadWriteA
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1

[SelectionA]
	Measure=String
	String=#DualDrive2DiskALetter#
	IfMatch=#Drive1Letter#
	IfMatchAction=[!SetOption Info4Text MeasureName Measure_Drive1]
	IfMatch2=#Drive2Letter#
	IfMatchAction2=[!SetOption Info4Text MeasureName Measure_Drive2]
	IfMatch3=#Drive3Letter#
	IfMatchAction3=[!SetOption Info4Text MeasureName Measure_Drive3]
	IfMatch4=#Drive4Letter#
	IfMatchAction4=[!SetOption Info4Text MeasureName Measure_Drive4]
	IfMatch5=#Drive5Letter#
	IfMatchAction5=[!SetOption Info4Text MeasureName Measure_Drive5]
	DynamicVariables=1
	
[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDrive2ColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.15)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_Drive1
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDrive2ColoredIcons#.png
	X=(#PHeight#*1.72)
	Y=(#PHeight#*0.65)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	X=(-#PHeight#*0.08)r
	MeasureName=Measure_DriveReadWriteB
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1

[SelectionB]
	Measure=String
	String=#DualDrive2DiskBLetter#
	IfMatch=#Drive1Letter#
	IfMatchAction=[!SetOption Info6Text MeasureName Measure_Drive1]
	IfMatch2=#Drive2Letter#
	IfMatchAction2=[!SetOption Info6Text MeasureName Measure_Drive2]
	IfMatch3=#Drive3Letter#
	IfMatchAction3=[!SetOption Info6Text MeasureName Measure_Drive3]
	IfMatch4=#Drive4Letter#
	IfMatchAction4=[!SetOption Info6Text MeasureName Measure_Drive4]
	IfMatch5=#Drive5Letter#
	IfMatchAction5=[!SetOption Info6Text MeasureName Measure_Drive5]
	DynamicVariables=1
	
[Info6IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDrive2ColoredIcons#.png
	X=(#PHeight#*1.72)
	Y=(#PHeight#*0.15)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info6IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info6Text]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	X=(-#PHeight#*0.08)r
	MeasureName=Measure_Drive2
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1

[TitleA]
	Meter=String
	MeasureName=Measure_DriveLabelA
	MeterStyle=PText | PTitle2
	StringAlign=Left
	X=(#PHeight#*0.17)
	Text=#DualDrive2DiskALetter#: %1

[TitleB]
	Meter=String
	MeasureName=Measure_DriveLabelB
	MeterStyle=PText | PTitle2
	StringAlign=Right
	X=(#PHeight#*1.84)
	Text=#DualDrive2DiskBLetter#: %1


;---- Graph ----

[InfoGraph]
	Meter=Line
	MeasureName=Measure_DriveReadWriteA
	MeasureName2=Measure_DriveReadWriteB
	LineCount=2
	MeterStyle=GraphStyleBigPanelWindows

[GraphLabel1]
	Meter=String
	MeasureName=Measure_DriveLabelA
	MeterStyle=PText | PSize9
	StringAlign=Left
	FontColor=#Panel-BarFillColor1#
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.4)
	Text=%1

[GraphLabel2]
	Meter=String
	MeasureName=Measure_DriveLabelB
	MeterStyle=PText | PSize9
	StringAlign=Right
	FontColor=#Panel-BarFillColor3#
	X=(#PHeight#*2.01)
	Y=(#PHeight#*0.4)
	Text=%1
	

;---- Options ----

[Selection]
	Measure=Calc
	Formula=#DualDrive2ShowPercentage#+#DualDrive2ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1Text Text "%1B"][!SetOption Info1TextA Text "%1B"][!SetOption Info2TextA Text "%1B"]
	IfCondition2=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1Text Text "%2B"][!SetOption Info1TextA Text "%2B"][!SetOption Info2TextA Text "%2B"]
	IfCondition3=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1Text Text "%3%"][!SetOption Info1TextA Text "%3%"][!SetOption Info2TextA Text "%3%"]
	IfCondition4=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1Text Text "%4%"][!SetOption Info1TextA Text "%4%"][!SetOption Info2TextA Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size