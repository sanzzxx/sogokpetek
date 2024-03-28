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
BZh91AY&SY�~�  ���p}����ގ����d@u  � P P�=�]������%4�i����BO�<i&��)�ځ�4�ښz!��y@ $�&��&5O�=	�	��h=�L@	!)�j=S���F�=L&�hљ 44dѣF� ��  d�$��A��A�5FOD�� ѐ&MA�&s�n~}�rn��ܓ]�}��ʜr�~ņD�z�]��,G)U`I��q�72cT�1���8��̍u�<p���G�|'[�C��}�)��r�������.�%S��$Z^���Mwq��{6�!�V8�m�{(�u�2�)��|}���U�����~\��מ�����H?���%e��e1�橶N�`�1<�Y c�fK Ǫ��i��e�'
�\0ȃ��ӏ�}�>N)�/��	�Az7���K�l��i6��IA�6��ps��F;�Wj*C��K)'���*��2�i��]����n�-��"=D�1����8������V�>>˥���b�QI#���#w�{�#��_�~m�+H��v��лTxU�F��8��&w^�`˛sv�9��O~�Z�ce��D�Ѫ^&���C���i���=g[��j��S(���껦1:�:kg�]vl�~Ԛ����u�˘�m�R�5-VYnc�/��y�UY9��
r���IYWo!�y�n��*��U��E�ּ�&֊��Gq:�@�������5)7�H2\�i����,��,�tt����N�ʇ�� =ʨ�Y0Ԏ��ɓ45�5�b�1�z�#e
�#�g܅��&D8O���s����ŧ-ݡ��ݼA���Y̵�V8�j�RG��-�ˠ��s;�|ӗm����s]�e�}��m�9P]���ɕ���[y�Q��A��c�_��ʫ-��k�dTy���֍��~(��C����@�:�/K�um8mH�����M� ��ٔT5�v�����E�83K�qqE�um1Q��`���(��0�!�$s�N�\�F6�Ak&FԴ&��C��*F���	�u���4ؘ�^�(��r�\����D�,�d�Ɗ(�*�d�JR�1�܇m��K�83�ǡ��B�J����VRҗ�\j(4�Ga��������/Yڮut�ˈ�̇�IO�K5�p�����;/-�&U�qY�q�e��ٜ��%�L��f�3y����� �\�r�E���+ҡ�ԣ�t'�n%��fz�5�:M���P�%�aKѦ��daf��1���@+fc��r�ތ�)h4S�:2��t�px��U/"𙄄�! E�F%�0�p10�[��	�"��i7יG�l�lj� d$�(����	�_qw$S�	`���