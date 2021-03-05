[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc


;---- Measures Power ----

[Measure_PWR_Status]
Measure				=Plugin
Plugin				=PowerPlugin
PowerState			=Status
UpdateDivider		=2
RegExpSubstitute	=1
Substitute			="0":"#VarBat0#" , "1":"#VarBat1#" , "2":"#VarBat2#" , "3":"#VarBat3#" , "4":"#VarBat4#"

[Measure_PWR_ACLine]
Measure				=Plugin
Plugin				=PowerPlugin
PowerState			=ACLine
UpdateDivider		=2
IfCondition			=(Measure_PWR_ACLine = 1)
IfTrueAction		=[!HideMeter LifeTimeText]
IfCondition2		=(Measure_PWR_ACLine = 0)
IfTrueAction2		=[!ShowMeter LifeTimeText]
DynamicVariables	=1

[Measure_PWR_Lifetime]
Measure				=Plugin
Plugin				=PowerPlugin
PowerState			=Lifetime
UpdateDivider		=2

[Measure_PWR_Percent]
Measure				=Plugin
Plugin				=PowerPlugin
PowerState			=Percent
UpdateDivider		=2
IfCondition			=(Measure_PWR_Percent = 0)
IfTrueAction		=[!SetVariable CurrentBatPercent 0]
IfCondition2		=(Measure_PWR_Percent > 0) && (Measure_PWR_Percent < 20)
IfTrueAction2		=[!SetVariable CurrentBatPercent 20]
IfCondition3		=(Measure_PWR_Percent > 19) && (Measure_PWR_Percent < 40)
IfTrueAction3		=[!SetVariable CurrentBatPercent 40]
IfCondition4		=(Measure_PWR_Percent > 39) && (Measure_PWR_Percent < 60)
IfTrueAction4		=[!SetVariable CurrentBatPercent 60]
IfCondition5		=(Measure_PWR_Percent > 59) && (Measure_PWR_Percent < 80)
IfTrueAction5		=[!SetVariable CurrentBatPercent 80]
IfCondition6		=(Measure_PWR_Percent > 79)
IfTrueAction6		=[!SetVariable CurrentBatPercent 100]


;---- Standard Meters ----

[BatteryIconA]
	Meter=Image
	ImageName=#@#Images\Icons\Battery#CurrentBatPercent##PowerColoredIcons#.png
	X=(#PHeight#*0.02)
	Y=(#PHeight#*-0.12)
	W=(#PHeight#*0.66)
	ImageRotate=90
	DynamicVariables=1
	UpdateDivider=2
[BatteryIconB]
	Meter=Image
	ImageName=#@#Images\Icons\Battery#CurrentBatPercent##PowerColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.66)
	ImageRotate=90
	Hidden=#PowerColoredIcons#
	DynamicVariables=1
	UpdateDivider=2

[BatteryPercent]
	Meter=String
	MeterStyle=PText | PInfo
	StringAlign=Center
	X=(#PHeight#*0.85)
	Y=(#PHeight#*0.05)
	MeasureName=Measure_PWR_Percent
	Text=%1%
	UpdateDivider=2
	
[PwrPlugIconA]
	Meter=Image
	ImageName=#@#Images\Icons\PWRPlug[Measure_PWR_ACLine]#PowerColoredIcons#.png
	X=(#PHeight#*0.550)
	Y=(-#PHeight#*0.06)
	W=(#PHeight#*0.4)
	DynamicVariables=1
	UpdateDivider=2	
[PwrPlugIconB]
	Meter=Image
	ImageName=#@#Images\Icons\PWRPlug[Measure_PWR_ACLine]#PowerColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.4)
	Hidden=#PowerColoredIcons#
	DynamicVariables=1
	UpdateDivider=2

[LifeTimeText]
	Meter=String
	MeterStyle=PText | PSize7
	StringAlign=Center
	X=(#PHeight#*0.85)
	Y=(#PHeight#*0.2)
	MeasureName=Measure_PWR_Lifetime
	Text=%1
	NumOfDecimals=3
	UpdateDivider=2

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[Shell:::{025A5937-A6BE-4686-A844-36FE4BEC8B6D}]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size