[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc
;---- Sensors ----
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
Instance			=#Drive7Letter#:
Index				=0
Whitelist			=#Drive7Letter#:

[Measure_DriveReadWrite]
Measure				=Calc
Formula				=[Measure_DriveReadWriteRaw:]
DynamicVariables	=1


;---- Standard HWiNFO Measures ----

[Measure_DriveTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive7-Temp_Id#
HWiNFOSensorInstance=#Drive7-Temp_Instance#
HWiNFOEntryId		=#Drive7-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive7SSD##Drive7ColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive7SSD##Drive7ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#Drive7ColoredIcons#
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
	MeasureName=Measure_MaxDrive7
	Text=#VarUsed#
	X=(#PHeight#*1.03)
	Y=(#PHeight#*0.068)

[Info2TextA]
	Meter=String
	MeterStyle=PText | PSize6
	MeasureName=Measure_DriveReadWrite
	MeasureName2=Measure_DriveTemp
	Text=%2[\x00B0]#TempUnit# | %1B/s
	NumOfDecimals=0
	AutoScale=1
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.185)
[Info2TextB]
	Meter=String
	MeterStyle=PText | PSize6
	StringAlign=Right
	MeasureName=Measure_MaxSwap
	Text=#Drive7Letter#:
	X=(#PHeight#*1.03)
	Y=(#PHeight#*0.186)


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive7ShowPercentage#+#Drive7ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#Drive7ShowPercentage# = 0) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1TextB Text "#VarUsed#"][!SetOption Info1TextA Text "%1B"]
	IfCondition2=(#Drive7ShowPercentage# = 0) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1TextB Text "#VarFree#"][!SetOption Info1TextA Text "%2B"]
	IfCondition3=(#Drive7ShowPercentage# = 1) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1TextB Text "#VarUsed#"][!SetOption Info1TextA Text "%3%"]
	IfCondition4=(#Drive7ShowPercentage# = 1) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1TextB Text "#VarFree#"][!SetOption Info1TextA Text "%4%"]
	DynamicVariables=1
	
	
;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
PaDrive7eter=perfmon/res

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size