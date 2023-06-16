import React, { useRef, useState } from 'react';
import { InputProps } from '@uikit/Input/Input';
import SingleSelectPanel from '@uikit/Select/SingleSelect/SingleSelectPanel/SingleSelectPanel';
import Popover from '@uikit/Popover/Popover';
import { SingleSelectOptions } from '@uikit/Select/Select.types';
import { useForwardRef } from '@uikit/hooks/useForwardRef';
import CommonSelectField from '@uikit/Select/CommonSelect/CommonSelectField/CommonSelectField';
import PopoverPanelDefault from '@uikit/Popover/PopoverPanelDefault/PopoverPanelDefault';
import { PopoverOptions } from '@uikit/Popover/Popover.types';

export type SelectProps<T> = SingleSelectOptions<T> &
  PopoverOptions &
  Omit<InputProps, 'endAdornment' | 'startAdornment' | 'readOnly' | 'onChange' | 'value'>;

function SelectComponent<T>(
  {
    options,
    value,
    onChange,
    noneLabel,
    maxHeight,
    isSearchable,
    searchPlaceholder,
    containerRef,
    placement,
    offset,
    dependencyWidth = 'min-parent',
    ...props
  }: SelectProps<T>,
  ref: React.ForwardedRef<HTMLInputElement>,
) {
  const [isOpen, setIsOpen] = useState(false);
  const localContainerRef = useRef(null);
  const containerReference = useForwardRef(localContainerRef, containerRef);

  const handleChange = (val: T | null) => {
    setIsOpen(false);
    onChange?.(val);
  };

  return (
    <div>
      <CommonSelectField
        {...props}
        ref={ref}
        onClick={() => setIsOpen((prev) => !prev)}
        isOpen={isOpen}
        defaultValue={(value ?? '').toString()}
        containerRef={containerReference}
      />
      <Popover
        isOpen={isOpen}
        onOpenChange={setIsOpen}
        triggerRef={localContainerRef}
        dependencyWidth={dependencyWidth}
        placement={placement}
        offset={offset}
      >
        <PopoverPanelDefault>
          <SingleSelectPanel
            options={options}
            value={value}
            onChange={handleChange}
            noneLabel={noneLabel}
            maxHeight={maxHeight}
            isSearchable={isSearchable}
            searchPlaceholder={searchPlaceholder}
          />
        </PopoverPanelDefault>
      </Popover>
    </div>
  );
}

const Select = React.forwardRef(SelectComponent) as <T>(
  _props: SelectProps<T>,
  _ref: React.ForwardedRef<HTMLInputElement>,
) => ReturnType<typeof SelectComponent>;

export default Select;
