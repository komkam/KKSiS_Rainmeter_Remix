[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


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

;---- Standard HWiNFO Measures ----

[Measure_DriveTemp]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive8-Temp_Id#
HWiNFOSensorInstance=#Drive8-Temp_Instance#
HWiNFOEntryId		=#Drive8-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveRead]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive8-ReadRate_Id#
HWiNFOSensorInstance=#Drive8-ReadRate_Instance#
HWiNFOEntryId		=#Drive8-ReadRate_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveWrite]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive8-WriteRate_Id#
HWiNFOSensorInstance=#Drive8-WriteRate_Instance#
HWiNFOEntryId		=#Drive8-WriteRate_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1


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
	ImageName=#@#Images\Icons\Temp#Drive8ColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.49)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#Drive8ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive8ColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=0
	AutoScale=1
	
[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive8ColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.15)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive8ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive8ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveRead
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive8ColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.15)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive8ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive8ColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveWrite
	Text=%1B/s
	NumOfDecimals=1
	AutoScale=1


;---- Bar ----

[Bar1]
Meter=Shape
MeterStyle=BarStyle-VRx1
UpdateDivider=1
Hidden=#Drive8HideGraph#

[Bar1Measure]
Meter=Bar
MeterStyle=BarStyle-VRx1Measure
MeasureName=Measure_DrivePercentage#Drive8ShowFreeSpace#
UpdateDivider=1
Hidden=#Drive8HideGraph#

[Bar1Stroke]
Meter=Shape
MeterStyle=BarStyle-VRx1Stroke
UpdateDivider=1
Hidden=#Drive8HideGraph#

[Title]
	Meter=String
	MeasureName=Measure_DriveLabel
	MeterStyle=PText | PTitle
	Text=#Drive8Letter#: #Drive8Name#

;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive8ShowPercentage#+#Drive8ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#Drive8ShowPercentage# = 0) && (#Drive8ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1TextB Text "#VarUsed# [\x2282] %1B"][!SetOption Info1TextA Text "%1B"]
	IfCondition2=(#Drive8ShowPercentage# = 0) && (#Drive8ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1TextB Text "#VarFree# [\x2282] %1B"][!SetOption Info1TextA Text "%2B"]
	IfCondition3=(#Drive8ShowPercentage# = 1) && (#Drive8ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1TextB Text "#VarUsed# [\x2282] %1B"][!SetOption Info1TextA Text "%3%"]
	IfCondition4=(#Drive8ShowPercentage# = 1) && (#Drive8ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1TextB Text "#VarFree# [\x2282] %1B"][!SetOption Info1TextA Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=["#Drive8Letter#:"]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size