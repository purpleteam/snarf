(require 'cl)
(cl-loop for i in (directory-files "." nil "js$") do
      (find-file i)
      (indent-region (point-min) (point-max) nil)
      (untabify (point-min) (point-max))
      (save-buffer)
      (kill-buffer))

