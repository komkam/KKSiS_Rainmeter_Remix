[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
;---- Sensors ----
@Include6=#@#HWiNFO-Sensors.inc


;---- Standard Windows Measures ----

[Measure_DriveSpaceMax]
Measure				=FreeDiskSpace
Drive				=#Drive6Letter#:
Total				=1
UpdateDivider		=-1

[Measure_DriveSpace1]
Measure				=FreeDiskSpace
Drive				=#Drive6Letter#:

[Measure_DriveSpace0]
Measure				=Calc
Formula				=Measure_DriveSpaceMax-Measure_DriveSpace1

[Measure_DriveLabel]
Measure				=FreeDiskSpace
Drive				=#Drive6Letter#:
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
HWiNFOSensorId		=#Drive6-Temp_Id#
HWiNFOSensorInstance=#Drive6-Temp_Instance#
HWiNFOEntryId		=#Drive6-Temp_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveActivity]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive6-TotalActivity_Id#
HWiNFOSensorInstance=#Drive6-TotalActivity_Instance#
HWiNFOEntryId		=#Drive6-TotalActivity_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveRead]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive6-ReadRate_Id#
HWiNFOSensorInstance=#Drive6-ReadRate_Instance#
HWiNFOEntryId		=#Drive6-ReadRate_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1

[Measure_DriveWrite]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive6-WriteRate_Id#
HWiNFOSensorInstance=#Drive6-WriteRate_Instance#
HWiNFOEntryId		=#Drive6-WriteRate_EntryId#
HWiNFOType			=CurrentValue
UpdateDivider		=1


;---- Standard Meter ----

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive6SSD##Drive6ColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.15)
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Drive#Drive6SSD##Drive6ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	Hidden=#Drive6ColoredIcons#
	DynamicVariables=1
[Info1TextA]
	Meter=String
	MeterStyle=PText | PSize0
	StringAlign=Left
	X=(#PHeight#*0.5)
	Y=(#PHeight#*0.1)
	MeasureName=Measure_DriveSpace0
	MeasureName2=Measure_DriveSpace1
	MeasureName3=Measure_DrivePercentage1
	MeasureName4=Measure_DrivePercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
[Info1TextB]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	MeasureName=Measure_DriveSpaceMax
	X=(#PHeight#*1.84)
	Y=(#PHeight#*0.08)
	Text=#VarUsed# [\x2282]#CRLF#%1B
	AutoScale=1
	NumOfDecimals=0
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive6ColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.65)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Read#Drive6ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive6ColoredIcons#
	DynamicVariables=1
[Info2Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveRead
	Text=%1MB/s
	NumOfDecimals=1

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive6ColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.15)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Write#Drive6ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive6ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_DriveWrite
	Text=%1MB/s
	NumOfDecimals=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#Drive6ColoredIcons#.png
	X=(#PHeight#*1.72)
	Y=(#PHeight#*0.65)
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Temp#Drive6ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive6ColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	X=(-#PHeight#*0.08)r
	MeasureName=Measure_DriveTemp
	Text=%1[\x00B0]#TempUnit#
	NumOfDecimals=1

[Info5IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#Drive6ColoredIcons#.png
	X=(#PHeight#*1.72)
	Y=(#PHeight#*0.15)r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	DynamicVariables=1
[Info5IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Usage#Drive6ColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.12)
	H=(#PHeight#*0.12)
	Hidden=#Drive6ColoredIcons#
	DynamicVariables=1
[Info5Text]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	X=(-#PHeight#*0.08)r
	MeasureName=Measure_DriveActivity
	Text=%1%
	NumOfDecimals=1

[Title]
	Meter=String
	MeasureName=Measure_DriveLabel
	MeterStyle=PText | PTitle2
	Text=#Drive6Letter#: #Drive6Name#


;---- Graph ----

[InfoGraph]
	Meter=Line
	MeasureName=Measure_DriveRead
	MeasureName2=Measure_DriveWrite
	LineCount=2
	MeterStyle=GraphStyleBigPanelWindows

[GraphLabel1]
	Meter=String
	MeterStyle=PText | PSize9
	StringAlign=Left
	FontColor=#Panel-BarFillColor1#
	X=(#PHeight#*0.07)
	Y=(#PHeight#*0.4)
	Text=Read

[GraphLabel2]
	Meter=String
	MeterStyle=PText | PSize9
	StringAlign=Right
	FontColor=#Panel-BarFillColor3#
	X=(#PHeight#*2.01)
	Y=(#PHeight#*0.4)
	Text=Write

;---- Options ----

[Selection]
	Measure=Calc
	Formula=#Drive6ShowPercentage#+#Drive6ShowFreeSpace#
	UpdateRate=-1
	IfCondition=(#Drive6ShowPercentage# = 0) && (#Drive6ShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1TextB Text "#VarUsed# [\x2282]#CRLF#%1B"][!SetOption Info1TextA Text "%1B"]
	IfCondition2=(#Drive6ShowPercentage# = 0) && (#Drive6ShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1TextB Text "#VarFree# [\x2282]#CRLF#%1B"][!SetOption Info1TextA Text "%2B"]
	IfCondition3=(#Drive6ShowPercentage# = 1) && (#Drive6ShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1TextB Text "#VarUsed# [\x2282]#CRLF#%1B"][!SetOption Info1TextA Text "%3%"]
	IfCondition4=(#Drive6ShowPercentage# = 1) && (#Drive6ShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1TextB Text "#VarFree# [\x2282]#CRLF#%1B"][!SetOption Info1TextA Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=["#Drive6Letter#:"]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size