[Variables]
;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc
;---- Sensors ----
@Include6=#@#Windows-Sensors.inc


;---- Standard Windows Measures ----

[Measure_MaxRAM]
Measure				=PhysicalMemory
Total				=1

[Measure_RAM0]
Measure				=PhysicalMemory

[Measure_RAM1]
Measure				=Calc
Formula				=Measure_MaxRAM-Measure_RAM0

[Measure_MaxSwap]
Measure				=SwapMemory
Total				=1

[Measure_Swap0]
Measure				=SwapMemory

[Measure_Swap1]
Measure				=Calc
Formula				=Measure_MaxSwap-Measure_Swap0

[Measure_RAMPercentage0]
Measure				=Calc
Formula				=100-100*(Measure_RAM0/Measure_MaxRAM)
MaxValue			=100
MinValue			=0

[Measure_RAMPercentage1]
Measure				=Calc
Formula				=100*(Measure_RAM0/Measure_MaxRAM)
MaxValue			=100
MinValue			=0

[Measure_SwapPercentage0]
Measure				=Calc
Formula				=100-100*(Measure_Swap0/Measure_MaxSwap)

[Measure_SwapPercentage1]
Measure				=Calc
Formula				=100*(Measure_Swap0/Measure_MaxSwap)


;---- Standard Meter

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.15)
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	DynamicVariables=1
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\DRAM#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info1TextA]
	Meter=String
	MeterStyle=PText | PSize0
	X=(#PHeight#*0.25)r
	Y=(-#PHeight#*0.05)r
	MeasureName=Measure_RAM0
	MeasureName2=Measure_RAM1
	MeasureName3=Measure_RAMPercentage1
	MeasureName4=Measure_RAMPercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
[Info1TextB]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	MeasureName=Measure_MaxRAM
	X=(#PHeight#*1.84)
	Y=(-#PHeight#*0.03)r
	Text=#VarUsed##CRLF#%1B
	AutoScale=1
	NumOfDecimals=0
	
[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Swap#RAMColoredIcons#.png
	X=(#PHeight#*0.238)
	Y=(#PHeight#*0.7)
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	DynamicVariables=1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Swap#RAMColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.19)
	H=(#PHeight#*0.19)
	Hidden=#RAMColoredIcons#
	DynamicVariables=1
[Info2TextA]
	Meter=String
	MeterStyle=PText | PSize0
	X=(#PHeight#*0.25)r
	Y=(-#PHeight#*0.05)r
	MeasureName=Measure_Swap0
	MeasureName2=Measure_Swap1
	MeasureName3=Measure_SwapPercentage1
	MeasureName4=Measure_SwapPercentage0
	Text=%1B
	NumOfDecimals=1
	AutoScale=1
[Info2TextB]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Right
	MeasureName=Measure_MaxSwap
	X=(#PHeight#*1.84)
	Y=(-#PHeight#*0.03)r
	Text=#VarUsed##CRLF#%1B
	AutoScale=1
	NumOfDecimals=0
	
[Title]
	Meter=String
	MeasureName=Measure_RAMName
	MeterStyle=PText | PTitle2
	Text=#RAMNameWin#


;---- Graph ----

[InfoGraph]
	Meter=Line
	MeasureName=Measure_RAM0
	LineCount=1
	MeterStyle=GraphStyleBigPanelWindows


;---- Options ----

[Selection]
	Measure=Calc
	Formula=#RAMShowPercentage#+#RAMShowFreeSpace#+#RAMShowRAMonly#
	UpdateRate=-1
	IfCondition=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 0)
	IfTrueAction=[!SetOption Info1TextB Text "#VarUsed##CRLF#(%1B RAM)"][!SetOption Info2TextB Text "#VarUsed##CRLF#(%1B Swap)"][!SetOption Info1TextA Text "%1B"][!SetOption Info2TextA Text "%1B"]
	IfCondition2=(#RAMShowPercentage# = 0) && (#RAMShowFreeSpace# = 1)
	IfTrueAction2=[!SetOption Info1TextB Text "#VarFree##CRLF#(%1B RAM)"][!SetOption Info2TextB Text "#VarFree##CRLF#(%1B Swap)"][!SetOption Info1TextA Text "%2B"][!SetOption Info2TextA Text "%2B"]
	IfCondition3=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 0)
	IfTrueAction3=[!SetOption Info1TextB Text "#VarUsed##CRLF#(%1B RAM)"][!SetOption Info2TextB Text "#VarUsed##CRLF#(%1B Swap)"][!SetOption Info1TextA Text "%3%"][!SetOption Info2TextA Text "%3%"]
	IfCondition4=(#RAMShowPercentage# = 1) && (#RAMShowFreeSpace# = 1)
	IfTrueAction4=[!SetOption Info1TextB Text "#VarFree##CRLF#(%1B RAM)"][!SetOption Info2TextB Text "#VarFree##CRLF#(%1B Swap)"][!SetOption Info1TextA Text "%4%"][!SetOption Info2TextA Text "%4%"]
	DynamicVariables=1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure SpecialFunction Run]

[SpecialFunction]
Measure=Plugin
Plugin=RunCommand
Parameter=perfmon/res

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size