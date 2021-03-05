[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
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

[Measure_DriveActivity]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive8-TotalActivity_Id#
HWiNFOSensorInstance=#Drive8-TotalActivity_Instance#
HWiNFOEntryId		=#Drive8-TotalActivity_EntryId#
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

[Info]
	Meter=String
	MeterStyle=PText | PInfo | PCenterBig
	MeasureName=Measure_DriveSpaceMax
	Y=(#PHeight#*0.03)
	Text=#VarUsed# [\x2282] %1B
	AutoScale=1
	NumOfDecimals=0
	
[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive8SSD##Drive8ColoredIcons#.png
	X=(#PHeight#*0.17)
	Y=(#PHeight#*0.20)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive8SSD##Drive8ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive8ColoredIcons#
	DynamicVariables=1
[Info1Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveSpace0
	MeasureName2=Measure_DriveSpace1
	MeasureName3=Measure_DrivePercentage1
	MeasureName4=Measure_DrivePercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#Drive8ColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
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

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive8ColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
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
	Text=%1 MB/s
	NumOfDecimals=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive8ColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
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
	Text=%1 MB/s
	NumOfDecimals=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#Drive8ColoredIcons#.png
	X=(-#PHeight#*0.2)r
	Y=(#PHeight#*0.16)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#Drive8ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive8ColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveActivity
	Text=%1 %
	NumOfDecimals=1
	
[Title]
	Meter=String
	MeasureName=Measure_DriveLabel
	MeterStyle=PText | PTitle | PCenterBig
	Text=#Drive8Letter#: #Drive8Name#


;---- Graph ----

[Info1Graph]
	Meter=Line
	MeasureName=Measure_DriveSpace1
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	X=(#PHeight#*0.97)
	Y=(#PHeight#*0.19)
	UpdateDivider=1
	
[Info2Graph]
	Meter=Line
	MeasureName=Measure_DriveTemp
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	Y=(#PHeight#*0.15)r
	UpdateDivider=1
	
[Info3Graph]
	Meter=Line
	MeasureName=Measure_DriveRead
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	Y=(#PHeight#*0.15)r
	UpdateDivider=1
	
[Info4Graph]
	Meter=Line
	MeasureName=Measure_DriveWrite
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO	
	Y=(#PHeight#*0.15)r
	UpdateDivider=1
	
[Info5Graph]
	Meter=Line
	MeasureName=Measure_DriveActivity
	LineCount=1
	MeterStyle=GraphStyleBigPanelHWiNFO
	Y=(#PHeight#*0.15)r
	UpdateDivider=1


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive8ShowPercentage#+#Drive8ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#Drive8ShowPercentage# = 0) && (#Drive8ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info Text "#VarUsed# [\x2282] %1B"][!SetOption Info1Text Text "%1B"]
	IfCondition2=(#Drive8ShowPercentage# = 0) && (#Drive8ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info Text "#VarFree# [\x2282] %1B"][!SetOption Info1Text Text "%2B"]
	IfCondition3=(#Drive8ShowPercentage# = 1) && (#Drive8ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info Text "#VarUsed# [\x2282] %1B"][!SetOption Info1Text Text "%3%"]
	IfCondition4=(#Drive8ShowPercentage# = 1) && (#Drive8ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info Text "#VarFree# [\x2282] %1B"][!SetOption Info1Text Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=["#Drive8Letter#:"]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size