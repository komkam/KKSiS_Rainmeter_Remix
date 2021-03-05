[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


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
	Y=(#PHeight#*0.2)
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
	Y=(#PHeight#*0.473)
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
	Y=(#PHeight#*0.46)
	NumOfDecimals=0
	AutoScale=1
[Info2TextB]
	Meter=String
	MeasureName=Measure_DriveReadWriteB
	MeterStyle=PText | PInfo
	StringAlign=Left
	Text=%1
	X=(#PHeight#*0.65)
	Y=(#PHeight#*0.46)
	NumOfDecimals=0
	AutoScale=1

[Info3Text]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterMid
	Y=(#PHeight#*0.6)
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
	IfTrueAction=[!SetOption Info Text "#VarUsed#"][!SetOption Info1Text Text "%1B"][!SetOption Info3Text Text "%1B"]
	IfCondition2=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text "#VarFree#"][!SetOption Info1Text Text "%2B"][!SetOption Info3Text Text "%2B"]
	IfCondition3=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text "#VarUsed#"][!SetOption Info1Text Text "%3%"][!SetOption Info3Text Text "%3%"]
	IfCondition4=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text "#VarFree#"][!SetOption Info1Text Text "%4%"][!SetOption Info3Text Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size