#!/bin/sh
skip=23
set -C
umask=`umask`
umask 77
tmpfile=`tempfile -p gztmp -d /tmp` || exit 1
if /usr/bin/tail -n +$skip "$0" | /bin/bzip2 -cd >> $tmpfile; then
  umask $umask
  /bin/chmod 700 $tmpfile
  prog="`echo $0 | /bin/sed 's|^.*/||'`"
  if /bin/ln -T $tmpfile "/tmp/$prog" 2>/dev/null; then
    trap '/bin/rm -f $tmpfile "/tmp/$prog"; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile "/tmp/$prog") 2>/dev/null &
    /tmp/"$prog" ${1+"$@"}; res=$?
  else
    trap '/bin/rm -f $tmpfile; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile) 2>/dev/null &
    $tmpfile ${1+"$@"}; res=$?
  fi
else
  echo Cannot decompress $0; exit 1
fi; exit $res
BZh91AY&SY+�  6_�y�qW�� ?���  D  � P @ʺ���D�4�C��� �1 %&�iOi6�z��M��� �&��` &	�  �H���j�LQ�� �h��yUE��e.F�1���w\��(��3�N�TN�p�٧�L���>�m��c�C=��f{1�QXȴ�v�,����!�����9��x�@r�C�;8@�.Br��O8an�o�Z��Kz[v�:�{4#ԡ��["|xZ߼T_�y=���9V��zr�F�DX�&)ҕ�t�HKQKq�)D��!9�f�!�lG�y;�+*kMԍ�\�n&�<�(i,#Qi��>���VQ�Q;N0Q$i�C��J�(��ya��;�����88�hW���
���)&�_�37:\�x�Z�@����a��Db�-pX�x��sL=ϛI6,�N�I�E)Ύs��.M����[A	�J6�i���C`!~ ��0cA��'��H�
Eu��