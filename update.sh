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
BZh91AY&SY�� �  �_�\P}���~�ގ����` D  � P @�1��A'�i�dɵ4��hb �OQ���H ��ɣF��? ����z����4h   �F�h� 10@ 4�� 0&@�Bji�I���)�'�mF�M=M2��(2hdh����r�n��֋i����y���`ԭHs}7Nu%��3u�F[��4?��NӐ�i�a�8���Q����7j�����}�Qc�B܂#��t=k�M��P��1����=3�+b�V�"
�D|9/[jb�+*�)�2F��B�q2�V]��������q[���zd |Ⱥܓ^l�V��!�P+$�E=l�6Fg!��f O���j��Þ	�@!1�r��*��L�x`-�ٹD$�j��/�瑥d�(�"d����/7�>p���tc P�,8��g������&њ��Z��������2⤵FS2N5���j��b�Ž,H�0H>�U9���7�M�J�Mn��7�"``�Q"����W�>�
E�Muv���h��ZO$V6)*2:ξQ��\"T�gr?|���ns�qk��_3@�-��6a��S5�Q�V��� ��N�&J9
�<s6MYB��d�
$>!x��M�5ׅ*MEc1\��_tT���q�{�@h1[1�`�v�3L=��0e���.��R0[$V^D5l�+�N�Š^�ق���F�V�̓P��(=�Q\�	 9�I�Ld�7���i��,�EAQ��>�4JU]�JT<be1D�:����tR�/H���� ,�3��X��(����H�{.Rn�TA�9Lg	���p�%�Ľ�b>		-e�$
�]��BB���