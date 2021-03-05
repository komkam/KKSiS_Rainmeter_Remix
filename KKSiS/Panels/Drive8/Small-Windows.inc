[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


;---- Standard Windows Measures ----

[Measure_DriveSpaceMax]
Measure				=FreeDiskSpace
Drive				=#Drive8Letter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpace1]
Measure				=FreeDiskSpace
Drive				=#Drive8Letter#:

[Measure_DriveSpace0]
Measure				=Calc
Formula				=Measure_DriveSpaceMax-Measure_DriveSpace1

[Measure_DriveLabel]
Measure				=FreeDiskSpace
Drive				=#Drive8Letter#:
Label				=1
UpdateDivider		=-1

[Measure_DrivePercentage0]
Measure				=Calc
Formula				=100-100*(Measure_DriveSpace0/Measure_DriveSpaceMax)
MaxValue			=100
MinValue			=0

[Measure_DrivePercentage1]
Measure				=Calc
Formula				=100*(Measure_DriveSpace0/Measure_DriveSpaceMax)
MaxValue			=100
MinValue			=0

[Measure_DriveReadWriteRaw]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=LogicalDisk
Counter				=Bytes/s
Instance			=#Drive8Letter#:
Index				=0
Whitelist			=#Drive8Letter#:

[Measure_DriveReadWrite]
Measure				=Calc
Formula				=[Measure_DriveReadWriteRaw:]
DynamicVariables	=1


;---- Standard Meter
	
[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive8SSD##Drive8ColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive8SSD##Drive8ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#Drive8ColoredIcons#
	DynamicVariables=1
[Info1TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveSpace0
	MeasureName2=Measure_DriveSpace1
	MeasureName3=Measure_DrivePercentage1
	MeasureName4=Measure_DrivePercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
[Info1TextB]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	MeasureName=Measure_MaxDrive8
	Text=#VarUsed#
	X=(#PHeight#*1.03)
	Y=(#PHeight#*0.068)

[Info2TextA]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveReadWrite
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
[Info2TextB]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	MeasureName=Measure_MaxSwap
	Text=#Drive8Letter#:
	X=(#PHeight#*1.03)
	Y=(#PHeight#*0.186)


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive8ShowPercentage#+#Drive8ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#Drive8ShowPercentage# = 0) && (#Drive8ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1TextB Text "#VarUsed#"][!SetOption Info1TextA Text "%1B"]
	IfCondition2=(#Drive8ShowPercentage# = 0) && (#Drive8ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1TextB Text "#VarFree#"][!SetOption Info1TextA Text "%2B"]
	IfCondition3=(#Drive8ShowPercentage# = 1) && (#Drive8ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1TextB Text "#VarUsed#"][!SetOption Info1TextA Text "%3%"]
	IfCondition4=(#Drive8ShowPercentage# = 1) && (#Drive8ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1TextB Text "#VarFree#"][!SetOption Info1TextA Text "%4%"]
	DynamicVariables=1
	
	
;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=["#Drive8Letter#:"]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size