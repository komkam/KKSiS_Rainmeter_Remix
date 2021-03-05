[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
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

[Info]
	Meter=String
	MeterStyle=PText | PInfo | PCenterMid
	MeasureName=Measure_DriveSpaceMax
	Y=(#PHeight#*0.03)
	Text=#VarUsed#


[Info1Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterMid
	Y=(#PHeight#*0.15)
	MeasureName=Measure_DriveSpaceA0
	MeasureName2=Measure_DriveSpaceA1
	MeasureName3=Measure_DrivePercentageA1
	MeasureName4=Measure_DrivePercentageA0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDrive2ColoredIcons#.png
	X=(#PHeight#*0.478)
	Y=(#PHeight#*0.4)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\ReadWrite#DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info2TextA]
	Meter=String
	MeasureName=Measure_DriveReadWriteA
	MeterStyle=PText | PInfo
	StringAlign=Right
	Text=%1
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.38)
	NumOfDecimals=0
	AutoScale=1
[Info2TextB]
	Meter=String
	MeasureName=Measure_DriveReadWriteB
	MeterStyle=PText | PInfo
	StringAlign=Left
	Text=%1
	X=(#PHeight#*0.65)
	Y=(#PHeight#*0.38)
	NumOfDecimals=0
	AutoScale=1

[SelectionA]
	Measure=String
	String=#DualDrive2DiskALetter#
	IfMatch=#Drive1Letter#
	IfMatchAction=[!SetOption Info3TextA MeasureName Measure_Drive1]
	IfMatch2=#Drive2Letter#
	IfMatchAction2=[!SetOption Info3TextA MeasureName Measure_Drive2]
	IfMatch3=#Drive3Letter#
	IfMatchAction3=[!SetOption Info3TextA MeasureName Measure_Drive3]
	IfMatch4=#Drive4Letter#
	IfMatchAction4=[!SetOption Info3TextA MeasureName Measure_Drive4]
	IfMatch5=#Drive5Letter#
	IfMatchAction5=[!SetOption Info3TextA MeasureName Measure_Drive5]
	DynamicVariables=1

[SelectionB]
	Measure=String
	String=#DualDrive2DiskBLetter#
	IfMatch=#Drive1Letter#
	IfMatchAction=[!SetOption Info3TextB MeasureName Measure_Drive1]
	IfMatch2=#Drive2Letter#
	IfMatchAction2=[!SetOption Info3TextB MeasureName Measure_Drive2]
	IfMatch3=#Drive3Letter#
	IfMatchAction3=[!SetOption Info3TextB MeasureName Measure_Drive3]
	IfMatch4=#Drive4Letter#
	IfMatchAction4=[!SetOption Info3TextB MeasureName Measure_Drive4]
	IfMatch5=#Drive5Letter#
	IfMatchAction5=[!SetOption Info3TextB MeasureName Measure_Drive5]
	DynamicVariables=1
	
[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDrive2ColoredIcons#.png
	X=(#PHeight#*0.478)
	Y=(#PHeight#*0.55)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info3TextA]
	Meter=String
	MeasureName=
	MeterStyle=PText | PInfo
	StringAlign=Right
	Text=%1[\x00B0]#TempUnit#
	X=(#PHeight#*0.43)
	Y=(#PHeight#*0.53)
	NumOfDecimals=0
	AutoScale=1
[Info3TextB]
	Meter=String
	MeasureName=
	MeterStyle=PText | PInfo
	StringAlign=Left
	Text=%1[\x00B0]#TempUnit#
	X=(#PHeight#*0.65)
	Y=(#PHeight#*0.53)
	NumOfDecimals=0
	AutoScale=1
	
[Info4Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterMid
	Y=(#PHeight#*0.65)
	MeasureName=Measure_DriveSpaceB0
	MeasureName2=Measure_DriveSpaceB1
	MeasureName3=Measure_DrivePercentageB1
	MeasureName4=Measure_DrivePercentageB0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[Title]
	Meter=String
	MeasureName=Measure_DriveLabel
	MeterStyle=PText | PTitle
	Text=#DualDrive2DiskALetter#:\  &  #DualDrive2DiskBLetter#:\


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#DualDrive2ShowPercentage#+#DualDrive2ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info Text "#VarUsed#"][!SetOption Info1Text Text "%1B"][!SetOption Info4Text Text "%1B"]
	IfCondition2=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text "#VarFree#"][!SetOption Info1Text Text "%2B"][!SetOption Info4Text Text "%2B"]
	IfCondition3=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text "#VarUsed#"][!SetOption Info1Text Text "%3%"][!SetOption Info4Text Text "%3%"]
	IfCondition4=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text "#VarFree#"][!SetOption Info1Text Text "%4%"][!SetOption Info4Text Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size