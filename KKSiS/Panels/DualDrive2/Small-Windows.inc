[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
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


;---- Standard Meter
	
[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDrive2SSD##DualDrive2ColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#DualDrive2SSD##DualDrive2ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#DualDrive2ColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveSpaceA0
	MeasureName2=Measure_DriveSpaceA1
	MeasureName3=Measure_DrivePercentageA1
	MeasureName4=Measure_DrivePercentageA0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)

[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveSpaceB0
	MeasureName2=Measure_DriveSpaceB1
	MeasureName3=Measure_DrivePercentageB1
	MeasureName4=Measure_DrivePercentageB0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	
	;---- Options ----

[Selection]
	Measure=Calc
	Formula=#DualDrive2ShowPercentage#+#DualDrive2ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1Text Text "%1B"][!SetOption Info2Text Text "%1B"]
	IfCondition2=(#DualDrive2ShowPercentage# = 0) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1Text Text "%2B"][!SetOption Info2Text Text "%2B"]
	IfCondition3=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1Text Text "%3%"][!SetOption Info2Text Text "%3%"]
	IfCondition4=(#DualDrive2ShowPercentage# = 1) && (#DualDrive2ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1Text Text "%4%"][!SetOption Info2Text Text "%4%"]
	DynamicVariables=1
	UpdateDivider=-1

	
;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size