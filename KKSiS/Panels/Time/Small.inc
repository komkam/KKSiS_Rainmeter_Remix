[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc


;---- Measures ----

[DateYear]
Measure=Time
Format=%Y
UpdateDivider=60

[DateMonth]
Measure=Time
Format=%m
UpdateDivider=60

[DateDay]
Measure=Time
Format=%d
UpdateDivider=1
DynamicVariables=1

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


;---- Meters ----

[CurrentDateEN]
Meter=String
MeasureName=DateDay
MeasureName2=DateMonth
MeasureName3=DateYear
MeterStyle=PText | PSize6
Text=%2-%1-%3
Hidden=1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.04)
Group=english

[CurrentDateDE]
Meter=String
MeasureName=DateDay
MeasureName2=DateMonth
MeasureName3=DateYear
MeterStyle=PText | PSize6
Text=%1.%2.%3
Hidden=0
X=(#PHeight#*0.08)
Y=(#PHeight#*0.04)
Group=german

[CurrentTime24h]
Meter=String
MeasureName=TimeHours24H
MeasureName2=TimeMinutes
MeterStyle=PText | PSize0
Text=%1:%2
StringAlign=Right
X=(#PHeight#*0.98)
Y=(#PHeight#*0.10)
Group=24h
Hidden=0

[CurrentTime12h]
Meter=String
MeasureName=TimeHours12H
MeasureName2=TimeMinutes
MeterStyle=PText | PSize0
Text=%1:%2
StringAlign=Right
X=(#PHeight#*0.98)
Y=(#PHeight#*0.10)
Group=12h
Hidden=1

[CurrentAMPM]
Meter=String
MeasureName=TimeAMPM
MeterStyle=PText | PSize6
Text=%1
StringAlign=Right
X=(#PHeight#*0.98)
Y=(#PHeight#*0.05)
Group=12H
Hidden=1

[CurrentWeekISO8601]
Meter=String
MeasureName=DateWeek
MeterStyle=PText | PSize6
StringAlign=Left
Text=#TIWeek# %1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.14)
Hidden=0

[CurrentWeek]
Meter=String
MeasureName=DateWeek2
MeterStyle=PText | PSize6
StringAlign=Left
Text=#TIWeek# %1
X=(#PHeight#*0.08)
Y=(#PHeight#*0.14)
Hidden=1


;---- Skin Functions ----

[TimeFormat]
Measure=String
String=#Panel-TIFormat#
IfMatch=12H
IfMatchAction=[!HideMeterGroup "24H"][!ShowMeterGroup "12H"]
IfMatch2=24H
IfMatchAction2=[!HideMeterGroup "12H"][!ShowMeterGroup "24H"]
UpdateDivier=-1

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

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size
