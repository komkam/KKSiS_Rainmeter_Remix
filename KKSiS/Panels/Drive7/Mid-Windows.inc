[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


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

[Measure_DriveReadRaw]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=LogicalDisk
Counter				=Disk Read Bytes/sec
Instance			=#Drive7Letter#:
Index				=0
Whitelist			=#Drive7Letter#:

[Measure_DriveRead]
Measure				=Calc
Formula				=[Measure_DriveReadRaw:]
DynamicVariables	=1

[Measure_DriveWriteRaw]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=LogicalDisk
Counter				=Disk Write Bytes/sec
Instance			=#Drive7Letter#:
Index				=0
Whitelist			=#Drive7Letter#:

[Measure_DriveWrite]
Measure				=Calc
Formula				=[Measure_DriveWriteRaw:]
DynamicVariables	=1


;---- Standard Meter ----

[Info1TextA]
	Meter=String
	MeterStyle=PText | PSize0 | PCenterMid
	Y=(#PHeight#*0.2)
	MeasureName=Measure_DriveSpace0
	MeasureName2=Measure_DriveSpace1
	MeasureName3=Measure_DrivePercentage1
	MeasureName4=Measure_DrivePercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
[Info1TextB]
	Meter=String
	MeterStyle=PText | PInfo | PCenterMid
	MeasureName=Measure_DriveSpaceMax
	Y=(#PHeight#*0.03)
	Text=#VarUsed# [\x2282] %1B
	AutoScale=1
	NumOfDecimals=0
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive7ColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.55)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive7ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive7ColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveRead
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive7ColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.7)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive7ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive7ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveWrite
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1

[Title]
	Meter=String
	MeasureName=Measure_DriveLabel
	MeterStyle=PText | PTitle
	Text=#Drive7Letter#: #Drive7NameWin#


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#Drive7HideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_DrivePercentage#Drive7ShowFreeSpace#
UpdateDivider=1
Hidden=#Drive7HideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#Drive7HideGraph#


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive7ShowPercentage#+#Drive7ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#Drive7ShowPercentage# = 0) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1TextB Text "#VarUsed# [\x2282] %1B"][!SetOption Info1TextA Text "%1B"]
	IfCondition2=(#Drive7ShowPercentage# = 0) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1TextB Text "#VarFree# [\x2282] %1B"][!SetOption Info1TextA Text "%2B"]
	IfCondition3=(#Drive7ShowPercentage# = 1) && (#Drive7ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1TextB Text "#VarUsed# [\x2282] %1B"][!SetOption Info1TextA Text "%3%"]
	IfCondition4=(#Drive7ShowPercentage# = 1) && (#Drive7ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1TextB Text "#VarFree# [\x2282] %1B"][!SetOption Info1TextA Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=["#Drive7Letter#:"]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size