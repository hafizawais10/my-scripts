select Definition

from

(

SELECT SM.Object_ID o, 1 ord, SM.Definition

FROM SYS.SQL_Modules As SM INNER JOIN SYS.Objects As Obj

ON SM.Object_ID = Obj.Object_ID WHERE Obj.Type = 'P'
and  obj.object_id  in (911601515,1889610716,638130260,910131229,1086131856,1134132027,1166132141,1246132426)
union all

SELECT SM.Object_ID o, 2 ord, 'GO'

FROM SYS.SQL_Modules As SM INNER JOIN SYS.Objects As Obj

ON SM.Object_ID = Obj.Object_ID WHERE Obj.Type = 'P'
and  obj.object_id  in (911601515,1889610716,638130260,910131229,1086131856,1134132027,1166132141,1246132426)

) a

order by o,ord