import React from 'react';
import cn from 'classnames';
import { FieldProps } from '@uikit/Field/Field.types';
import { useFieldStyles } from '@uikit/Field/useFieldStyles';

export interface InputProps extends FieldProps, React.InputHTMLAttributes<HTMLInputElement> {
  endAdornment?: React.ReactNode;
  startAdornment?: React.ReactNode;
}
const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className,
      variant = 'primary',
      hasError = false,
      startAdornment = null,
      endAdornment = null,
      disabled,
      ...props
    },
    ref,
  ) => {
    const { fieldClasses, fieldContentClasses: inputClasses } = useFieldStyles({ variant, hasError, disabled });

    return (
      <div className={cn(className, fieldClasses)}>
        {startAdornment}
        <input ref={ref} className={inputClasses} {...props} disabled={disabled} />
        {endAdornment}
      </div>
    );
  },
);

Input.displayName = 'Input';
export default Input;
