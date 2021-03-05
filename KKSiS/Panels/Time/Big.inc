[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc

;---- Celendar Variables ----
DayLabels=#TIWD0#|#TIWD1#|#TIWD2#|#TIWD3#|#TIWD4#|#TIWD5#|#TIWD6#
MonthLabels=#TIMonth1#|#TIMonth2#|#TIMonth3#|#TIMonth4#|#TIMonth5#|#TIMonth6#|#TIMonth7#|#TIMonth8#|#TIMonth9#|#TIMonth10#|#TIMonth11#|#TIMonth12#
LabelText={$MName} {$Year}
UseLocalMonths=0
ShowEvents=0
HideLastWeek=0
ShowMoonPhases=0
ShowEvents=0
Eventfile=


;---- Measures ----

[TimeSeconds]
Measure=Time
Format=%S
UpdateDivider=1

[TimeHours24H]
Measure=Time
Format=%H

[TimeHours12H]
Measure=Time
Format=%I

[TimeMinutes]
Measure=Time
Format=%M

[TimeAMPM]
Measure=Time
Format=%p
UpdateDivider=10

[DateWeek]
Measure=Time
Format=%V
UpdateDivider=10

[DateWeek2]
Measure=Time
Format=%U
UpdateDivider=10

[DateWeekNo]
Measure=Time
Format=%#w
UpdateDivider=10


;---- Week ----

[WeekdaymarkerNonColored]
Meter=Shape
Shape=Rectangle (#PHeight#*0.38),(#PHeight#*0.375),(#PHeight#*0.28),(#PHeight#*0.12),(#PHeight#*0.01) | Fill Color 0,0,0,0 | StrokeWidth (#PHeight#*0.012) | Stroke Color #Panel-FontColor#
DynamicVariables=1
Group=Weekday
Hidden=1
DynamicVariables=1

[WeekdaymarkerColored]
Meter=Shape
Shape=Rectangle (#PHeight#*0.38),(#PHeight#*0.375),(#PHeight#*0.28),(#PHeight#*0.12),(#PHeight#*0.01) | Fill Color 0,0,0,0 | StrokeWidth (#PHeight#*0.012) | Stroke Color #Panel-BarFillColor1#
DynamicVariables=1
Group=Weekday
Hidden=0

[WeekDay1]
Meter=String
MeterStyle=PText | PSize8
StringAlign=Left
X=(#PHeight#*0.73)
Y=(#PHeight#*0.11)
Text=2
DynamicVariables=1
Group=Weekday

[WeekDay2]
Meter=String
MeterStyle=PText | PSize7
StringAlign=Left
X=(#PHeight#*0.655)
Y=(#PHeight#*0.18)
Text=2
DynamicVariables=1
Group=Weekday

[WeekDay3]
Meter=String
MeterStyle=PText | PSize6
StringAlign=Left
X=(#PHeight#*0.58)
Y=(#PHeight#*0.255)
Text=3
DynamicVariables=1
Group=Weekday

[WeekDay4]
Meter=String
MeterStyle=PText | PSize4
StringAlign=Center
X=(#PHeight#*0.52)
Y=(#PHeight#*0.36)
Text=4
DynamicVariables=1
Group=Weekday

[WeekDay5]
Meter=String
MeterStyle=PText | PSize6
StringAlign=Left
X=(#PHeight#*0.335)
Y=(#PHeight#*0.5)
Text=5
DynamicVariables=1
Group=Weekday

[WeekDay6]
Meter=String
MeterStyle=PText | PSize7
StringAlign=Left
X=(#PHeight#*0.25)
Y=(#PHeight#*0.59)
Text=6
DynamicVariables=1
Group=Weekday

[WeekDay7]
Meter=String
MeterStyle=PText | PSize8
StringAlign=Left
X=(#PHeight#*0.175)
Y=(#PHeight#*0.67)
Text=7
DynamicVariables=1
Group=Weekday
[WeekDay]
Measure=Calc
Formula=DateWeekNo
IfCondition=WeekDay = 0
IfTrueAction=[!SetOption WeekDay1 Text #TIWD3#][!SetOption WeekDay2 Text #TIWD2#][!SetOption WeekDay3 Text #TIWD1#][!SetOption WeekDay4 Text #TIWD0#][!SetOption WeekDay5 Text #TIWD6#][!SetOption WeekDay6 Text #TIWD5#][!SetOption WeekDay7 Text #TIWD4#]
IfCondition2=WeekDay = 1
IfTrueAction2=[!SetOption WeekDay1 Text #TIWD4#][!SetOption WeekDay2 Text #TIWD3#][!SetOption WeekDay3 Text #TIWD2#][!SetOption WeekDay4 Text #TIWD1#][!SetOption WeekDay5 Text #TIWD0#][!SetOption WeekDay6 Text #TIWD6#][!SetOption WeekDay7 Text #TIWD5#]
IfCondition3=WeekDay = 2
IfTrueAction3=[!SetOption WeekDay1 Text #TIWD5#][!SetOption WeekDay2 Text #TIWD4#][!SetOption WeekDay3 Text #TIWD3#][!SetOption WeekDay4 Text #TIWD2#][!SetOption WeekDay5 Text #TIWD1#][!SetOption WeekDay6 Text #TIWD0#][!SetOption WeekDay7 Text #TIWD6#]
IfCondition4=WeekDay = 3
IfTrueAction4=[!SetOption WeekDay1 Text #TIWD6#][!SetOption WeekDay2 Text #TIWD5#][!SetOption WeekDay3 Text #TIWD4#][!SetOption WeekDay4 Text #TIWD3#][!SetOption WeekDay5 Text #TIWD2#][!SetOption WeekDay6 Text #TIWD1#][!SetOption WeekDay7 Text #TIWD0#]
IfCondition5=WeekDay = 4
IfTrueAction5=[!SetOption WeekDay1 Text #TIWD0#][!SetOption WeekDay2 Text #TIWD6#][!SetOption WeekDay3 Text #TIWD5#][!SetOption WeekDay4 Text #TIWD4#][!SetOption WeekDay5 Text #TIWD3#][!SetOption WeekDay6 Text #TIWD2#][!SetOption WeekDay7 Text #TIWD1#]
IfCondition6=WeekDay = 5
IfTrueAction6=[!SetOption WeekDay1 Text #TIWD1#][!SetOption WeekDay2 Text #TIWD0#][!SetOption WeekDay3 Text #TIWD6#][!SetOption WeekDay4 Text #TIWD5#][!SetOption WeekDay5 Text #TIWD4#][!SetOption WeekDay6 Text #TIWD3#][!SetOption WeekDay7 Text #TIWD2#]
IfCondition7=WeekDay = 6
IfTrueAction7=[!SetOption WeekDay1 Text #TIWD2#][!SetOption WeekDay2 Text #TIWD1#][!SetOption WeekDay3 Text #TIWD0#][!SetOption WeekDay4 Text #TIWD6#][!SetOption WeekDay5 Text #TIWD5#][!SetOption WeekDay6 Text #TIWD4#][!SetOption WeekDay7 Text #TIWD3#]
UpdateDivider=10


;---- Time ----

[CurrentTime24h]
Meter=String
MeasureName=TimeHours24H
MeasureName2=TimeMinutes
MeterStyle=PText | PSize0
Text=%1:%2
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.64)
Group=24h
Hidden=0

[CurrentTime12h]
Meter=String
MeasureName=TimeHours12H
MeasureName2=TimeMinutes
MeterStyle=PText | PSize0
Text=%1:%2
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.64)
Group=12h
Hidden=1

[CurrentSecs]
Meter=String
MeasureName=TimeSeconds
MeterStyle=PText | PSize5
Text=%1
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.56)
Hidden=#TIHideSeconds#

[CurrentAMPM]
Meter=String
MeasureName=TimeAMPM
MeterStyle=PText | PSize5
Text=%1
StringAlign=Right
X=(#PHeight#*0.94)
Y=(#PHeight#*0.88)
Group=12H
Hidden=1

[CurrentWeekISO8601]
Meter=String
MeasureName=DateWeek
MeterStyle=PText | PSize5
StringAlign=Left
Text=#TIWeek# %1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.04)
Hidden=0

[CurrentWeek]
Meter=String
MeasureName=DateWeek2
MeterStyle=PText | PSize5
StringAlign=Left
Text=#TIWeek# %1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.04)
Hidden=1

[TimeFormat]
Measure=String
String=#Panel-TIFormat#
IfMatch=12H
IfMatchAction=[!HideMeterGroup "24H"][!ShowMeterGroup "12H"]
IfMatch2=24H
IfMatchAction2=[!HideMeterGroup "12H"][!ShowMeterGroup "24H"]
UpdateDivier=-1


;---- Skin Functions ----

[LanguageFormat]
Measure=String
String=#Panel-Language#
IfMatch=german
IfMatchAction=[!HideMeterGroup "english"][!ShowMeterGroup "german"]
IfMatch2=english
IfMatchAction2=[!HideMeterGroup "german"][!ShowMeterGroup "english"]
UpdateDivier=-1

[CWeekFormat]
Measure=String
String=#TIShowCWIsoFormat#
IfMatch=1
IfMatchAction=[!HideMeter "CurrentWeek"][!ShowMeter "CurrentWeekISO8601"]
IfMatch2=0
IfMatchAction2=[!HideMeter "CurrentWeekISO8601"][!ShowMeter "CurrentWeek"]
UpdateDivier=-1

[WeekdayMarkerFormat]
Measure=String
String=#TIShowColoredWeekday#
IfMatch=1
IfMatchAction=[!HideMeter "WeekdaymarkerNonColored"][!ShowMeter "WeekdaymarkerColored"]
IfMatch2=0
IfMatchAction2=[!HideMeter "WeekdaymarkerColored"][!ShowMeter "WeekdaymarkerNonColored"]
UpdateDivier=-1


;---- Calendar ----

[Lua]
Measure=Script
ScriptFile=#@#Tools\CScript.lua


;---- Weekday Labels ----

[LblTxtStart]
X=(#PHeight#*1.12)
Y=(#PHeight#*0.06)

[LblTxtSty]
FontFace=Calibri
FontColor=#Panel-FontColor#
StringStyle=Normal
StringAlign=Center
AntiAlias=1
DynamicVariables=1
FontSize=(#PHeight#*0.04)
SolidColor=#Panel-BGShadowColor#,50
H=(#PHeight#*0.06)
W=(#PHeight#*0.120)
X=(#PHeight#*0.140)r
Y=0r

[l1]
Meter=string
[l2]
Meter=string
[l3]
Meter=string
[l4]
Meter=string
[l5]
Meter=string
[l6]
Meter=string
[l7]
Meter=string

[CalLine]
Meter=Shape
Shape=Rectangle (#PHeight#*1.06),(#PHeight#*0.135),(#PHeight#*0.96),(#PHeight#*0.006),0 | StrokeWidth 0 | Fill Color #Panel-FontColor#
DynamicVariables=1

[WeekEndMarker1]
Meter=Shape
Shape=Rectangle (#PHeight#*1.74),(#PHeight#*0.164),(#PHeight#*0.14),(#PHeight#*0.67) | StrokeWidth 0 | Fill LinearGradient WEStyle
WEStyle=0 | 0,0,0,0 ; 1.0 | #Panel-BGShadowColor#,(60*#StartOnMonday#) ; 0.5 | 0,0,0,0 ; 0.0
DynamicVariables=1

[WeekEndMarker2]
Meter=Shape
Shape=Rectangle (#PHeight#*1.88),(#PHeight#*0.164),(#PHeight#*0.14),(#PHeight#*0.67) | StrokeWidth 0 | Fill LinearGradient WEStyle
WEStyle=0 | 0,0,0,0 ; 1.0 | #Panel-BGShadowColor#,(80*#StartOnMonday#) ; 0.5 | 0,0,0,0 ; 0.0
DynamicVariables=1

[WeekEndMarker3]
Meter=Shape
Shape=Rectangle (#PHeight#*1.88),(#PHeight#*0.164),(#PHeight#*0.14),(#PHeight#*0.67) | StrokeWidth 0 | Fill LinearGradient WEStyle
WEStyle=0 | 0,0,0,0 ; 1.0 | #Panel-BGShadowColor#,60 ; 0.5 | 0,0,0,0 ; 0.0
Hidden=#StartOnMonday#
DynamicVariables=1

[WeekEndMarker4]
Meter=Shape
Shape=Rectangle (#PHeight#*1.04),(#PHeight#*0.164),(#PHeight#*0.14),(#PHeight#*0.67) | StrokeWidth 0 | Fill LinearGradient WEStyle
WEStyle=0 | 0,0,0,0 ; 1.0 | #Panel-BGShadowColor#,80 ; 0.5 | 0,0,0,0 ; 0.0
Hidden=#StartOnMonday#
DynamicVariables=1


;---- Days ----

[LblCurrSty]
StringStyle=Bold

[FirstDay]
X=(#PHeight#*1.12)
Y=(#PHeight#*0.14)

[TextStyle]
FontFace=Calibri
FontColor=#Panel-FontColor#
StringStyle=Normal
StringAlign=Center
AntiAlias=1
DynamicVariables=1
FontSize=(#PHeight#*0.07)
H=(#PHeight#*0.054)
W=(#PHeight#*0.120)
X=(#PHeight#*0.140)r
Y=0r

[NewWk]
Y=(#PHeight#*0.120)r
X=(#PHeight#*1.120)

[CurrentDay]
StringStyle=Bold
FontColor=#Panel-BarFillColor1#
SolidColor=#Panel-BGShadowColor#,50
H=(#PHeight#*0.11)
W=(#PHeight#*0.120)

[PreviousMonth]
FontColor=120,120,120

[NextMonth]
FontColor=120,120,120

[mDay1]
Meter=string
[mDay2]
Meter=string
[mDay3]
Meter=string
[mDay4]
Meter=string
[mDay5]
Meter=string
[mDay6]
Meter=string
[mDay7]
Meter=string

[mDay8]
Meter=string
[mDay9]
Meter=string
[mDay10]
Meter=string
[mDay11]
Meter=string
[mDay12]
Meter=string
[mDay13]
Meter=string
[mDay14]
Meter=string

[mDay15]
Meter=string
[mDay16]
Meter=string
[mDay17]
Meter=string
[mDay18]
Meter=string
[mDay19]
Meter=string
[mDay20]
Meter=string
[mDay21]
Meter=string

[mDay22]
Meter=string
[mDay23]
Meter=string
[mDay24]
Meter=string
[mDay25]
Meter=string
[mDay26]
Meter=string
[mDay27]
Meter=string
[mDay28]
Meter=string

[mDay29]
Meter=string
[mDay30]
Meter=string
[mDay31]
Meter=string
[mDay32]
Meter=string
[mDay33]
Meter=string
[mDay34]
Meter=string
[mDay35]
Meter=string

[mDay36]
Meter=string
[mDay37]
Meter=string
[mDay38]
Meter=string
[mDay39]
Meter=string
[mDay40]
Meter=string
[mDay41]
Meter=string
[mDay42]
Meter=string


;---- Month & Year ----

[mLabel]
Meter=String
MeterStyle=PText | PSize5
StringAlign=Center
X=(#PHeight#*1.54)
Y=(#PHeight#*0.88)
Text=#MonthLabel#

[ControlForward]
Meter=Image
ImageName=#@#Images\Buttons\BtnNext.png
ImageTint=#Panel-ButtonColor#
X=(#PHeight#*1.91)
Y=(#PHeight#*0.9)
H=(#PHeight#*0.1)
W=(#PHeight#*0.1)	
DynamicVariables=1
MouseOverAction=[!SetOption ControlForward ImageTint #Panel-BarFillColor1#][!Update]
MouseLeaveAction=[!SetOption ControlForward ImageTint #Panel-ButtonColor#][!Update]
LeftMouseUpAction=[!CommandMeasure "Lua" "Move(1)"][!Update]

[ControlBack]
Meter=Image
ImageName=#@#Images\Buttons\BtnPrev.png
ImageTint=#Panel-ButtonColor#
X=(#PHeight#*1.07)	
Y=(#PHeight#*0.9)
H=(#PHeight#*0.1)		
W=(#PHeight#*0.1)		
DynamicVariables=1
MouseOverAction=[!SetOption ControlBack ImageTint #Panel-BarFillColor1#][!Update]
MouseLeaveAction=[!SetOption ControlBack ImageTint #Panel-ButtonColor#][!Update]
LeftMouseUpAction=[!CommandMeasure "Lua" "Move(-1)"][!Update]


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size
